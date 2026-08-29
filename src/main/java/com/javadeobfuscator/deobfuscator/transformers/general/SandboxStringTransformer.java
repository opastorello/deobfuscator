package com.javadeobfuscator.deobfuscator.transformers.general;

import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import com.javadeobfuscator.deobfuscator.sandbox.SandboxExecutor;
import com.javadeobfuscator.deobfuscator.transformers.Transformer;
import com.javadeobfuscator.deobfuscator.utils.Utils;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Obfuscator-agnostic string decryption that <em>executes</em> the decryption routines of the input inside an
 * isolated JVM process ({@link SandboxExecutor}) instead of emulating them. Works for any class-file version the
 * running JDK supports and covers the two patterns used by practically every obfuscator (Zelix, Allatori, Stringer,
 * DashO, Paramorphism, Skidfuscator, home-grown ones, ...):
 * <ol>
 *     <li><b>Static field strings</b>: strings (or {@code String[]} pools) decrypted in {@code <clinit>} and stored
 *     in static fields. The class is initialised in the sandbox, the resulting values are read back and every
 *     {@code GETSTATIC} (plus {@code AALOAD} with a constant index) is replaced by an {@code LDC}.</li>
 *     <li><b>Constant-argument decrypt calls</b>: {@code INVOKESTATIC} of a method of the input that returns
 *     {@code String} and whose arguments are all constants ({@code (II)String}, {@code (String)String},
 *     {@code (J)String}, ...). The call is executed in the sandbox and replaced by an {@code LDC}. Decryptors
 *     that inspect the call stack (ZKM "caller-sensitive" mode) are invoked through a generated trampoline class
 *     carrying the original caller class/method name.</li>
 * </ol>
 * Decryptor methods that end up unreferenced are removed when {@link Config#isRemoveDecryptors()} is set.
 * <p>
 * <b>The obfuscated code really runs.</b> The sandbox is a separate process with a throw-away home/temp dir,
 * a heap cap, a timeout, and (on JDK &lt; 24) a security manager that blocks network, file writes, exec and exit.
 * Do not run it on inputs you do not trust at all on a machine you care about.
 */
@TransformerConfig.ConfigOptions(configClass = SandboxStringTransformer.Config.class)
public class SandboxStringTransformer extends Transformer<SandboxStringTransformer.Config> {

    private static final Set<String> CALLER_SENSITIVE_MARKERS = new HashSet<>(Arrays.asList(
            "getStackTrace", "getCallerClass", "lookupClass", "StackWalker", "getStackTraceElement", "fillInStackTrace"
    ));

    private SandboxExecutor sandbox;
    private int replaced;
    private int failed;

    @Override
    public boolean transform() throws Throwable {
        Pattern ownerFilter = getConfig().getOwnerFilter() == null ? null : Pattern.compile(getConfig().getOwnerFilter());
        if (getConfig().isDryRun()) {
            analyzeDryRun(ownerFilter);
            return false;
        }
        List<File> cp = new ArrayList<>();
        cp.add(getDeobfuscator().getConfig().getInput());
        addJars(cp, getDeobfuscator().getConfig().getLibraries());
        addJars(cp, getDeobfuscator().getConfig().getPath());
        if (getConfig().getExtraClasspath() != null) {
            cp.addAll(getConfig().getExtraClasspath());
        }
        sandbox = new SandboxExecutor(cp, getConfig().getJava(), getConfig().getTimeoutMillis(), getConfig().getMaxHeapMb(), getConfig().getJvmArgs());
        try {
            if (getConfig().isStaticFields()) {
                transformStaticFields(ownerFilter);
            }
            if (getConfig().isMethodCalls()) {
                transformMethodCalls(ownerFilter);
            }
        } finally {
            sandbox.close();
        }
        logger.info("[SandboxStringTransformer] Replaced {} string(s), {} call(s)/field(s) could not be resolved", replaced, failed);
        return replaced > 0;
    }

    private static void addJars(List<File> target, List<File> files) {
        if (files == null) {
            return;
        }
        for (File f : files) {
            if (f.isFile()) {
                target.add(f);
            } else if (f.isDirectory() && !new File(f, "lib").isDirectory()) {
                File[] jars = f.listFiles(c -> c.getName().endsWith(".jar"));
                if (jars != null) {
                    target.addAll(Arrays.asList(jars));
                }
            }
        }
    }

    // ------------------------------------------------------------------ dry run: report coverage, touch nothing

    /**
     * Reports how many static-field pools and {@code INVOKESTATIC} decrypt calls would be resolved by this
     * transformer, without starting the sandbox, executing a single instruction of the input, or modifying any
     * bytecode. Safe to run on inputs you do not want to (or cannot) actually execute.
     */
    private void analyzeDryRun(Pattern ownerFilter) {
        Set<String> writtenOutsideClinit = new HashSet<>();
        for (ClassNode cn : classNodes()) {
            for (MethodNode mn : cn.methods) {
                if (mn.name.equals("<clinit>")) {
                    continue;
                }
                for (AbstractInsnNode ain : mn.instructions) {
                    if (ain.getOpcode() == PUTSTATIC) {
                        FieldInsnNode fin = (FieldInsnNode) ain;
                        writtenOutsideClinit.add(fin.owner + "." + fin.name);
                    }
                }
            }
        }

        int clinitStringFields = 0, clinitStringArrayFields = 0;
        for (ClassNode cn : classNodes()) {
            if (ownerFilter != null && !ownerFilter.matcher(cn.name).matches()) {
                continue;
            }
            MethodNode clinit = cn.methods.stream().filter(m -> m.name.equals("<clinit>")).findFirst().orElse(null);
            if (clinit == null) {
                continue;
            }
            for (AbstractInsnNode ain : clinit.instructions) {
                if (ain.getOpcode() != PUTSTATIC) {
                    continue;
                }
                FieldInsnNode fin = (FieldInsnNode) ain;
                if (!fin.owner.equals(cn.name) || writtenOutsideClinit.contains(fin.owner + "." + fin.name)) {
                    continue;
                }
                if (fin.desc.equals("Ljava/lang/String;")) {
                    clinitStringFields++;
                } else if (fin.desc.equals("[Ljava/lang/String;")) {
                    clinitStringArrayFields++;
                }
            }
        }

        int constCallSites = 0, callerSensitiveSites = 0, nonConstCallSites = 0;
        Set<String> constDecryptMethods = new HashSet<>();
        Set<String> callerSensitiveMethods = new HashSet<>();
        Map<Integer, Integer> argHisto = new TreeMap<>();

        for (ClassNode cn : classNodes()) {
            for (MethodNode mn : cn.methods) {
                for (AbstractInsnNode ain = mn.instructions.getFirst(); ain != null; ain = ain.getNext()) {
                    if (ain.getOpcode() != INVOKESTATIC) {
                        continue;
                    }
                    MethodInsnNode min = (MethodInsnNode) ain;
                    ClassNode owner = classes.get(min.owner);
                    if (owner == null || !Type.getReturnType(min.desc).getDescriptor().equals("Ljava/lang/String;")) {
                        continue;
                    }
                    if (ownerFilter != null && !ownerFilter.matcher(min.owner).matches()) {
                        continue;
                    }
                    Type[] argTypes = Type.getArgumentTypes(min.desc);
                    if (argTypes.length > getConfig().getMaxArgs()) {
                        continue;
                    }
                    MethodNode target = owner.methods.stream().filter(m -> m.name.equals(min.name) && m.desc.equals(min.desc)).findFirst().orElse(null);
                    if (target == null || (target.access & ACC_STATIC) == 0) {
                        continue;
                    }
                    String key = min.owner + "." + min.name + min.desc;
                    Object[] args = new Object[argTypes.length];
                    List<AbstractInsnNode> argInsns = new ArrayList<>();
                    if (collectConstantArgs(ain, argTypes, args, argInsns)) {
                        constCallSites++;
                        constDecryptMethods.add(key);
                        argHisto.merge(argTypes.length, 1, Integer::sum);
                        if (isCallerSensitive(owner, target, new HashSet<>())) {
                            callerSensitiveSites++;
                            callerSensitiveMethods.add(key);
                        }
                    } else {
                        nonConstCallSites++;
                    }
                }
            }
        }

        logger.info("[SandboxStringTransformer] Dry run: no code was executed and no bytecode was modified");
        logger.info("[SandboxStringTransformer]   <clinit> static String field(s):        {}", clinitStringFields);
        logger.info("[SandboxStringTransformer]   <clinit> static String[] pool field(s): {}", clinitStringArrayFields);
        logger.info("[SandboxStringTransformer]   INVOKESTATIC->String call site(s) with constant args (resolvable today): {} ({} distinct decryptor signature(s))",
                constCallSites, constDecryptMethods.size());
        logger.info("[SandboxStringTransformer]     of which caller-sensitive, resolved via trampoline: {} ({} method(s))",
                callerSensitiveSites, callerSensitiveMethods.size());
        logger.info("[SandboxStringTransformer]   INVOKESTATIC->String call site(s) with a non-constant argument (NOT resolvable today): {}", nonConstCallSites);
        logger.info("[SandboxStringTransformer]   argument-count histogram of resolvable call sites: {}", argHisto);
    }

    // ------------------------------------------------------------------ pattern 1: static fields

    private void transformStaticFields(Pattern ownerFilter) {
        // Fields written outside <clinit> are not constants.
        Set<String> writtenOutsideClinit = new HashSet<>();
        for (ClassNode cn : classNodes()) {
            for (MethodNode mn : cn.methods) {
                if (mn.name.equals("<clinit>")) {
                    continue;
                }
                for (AbstractInsnNode ain : mn.instructions) {
                    if (ain.getOpcode() == PUTSTATIC) {
                        FieldInsnNode fin = (FieldInsnNode) ain;
                        writtenOutsideClinit.add(fin.owner + "." + fin.name);
                    }
                }
            }
        }

        Map<String, Object> values = new HashMap<>();
        for (ClassNode cn : classNodes()) {
            if (ownerFilter != null && !ownerFilter.matcher(cn.name).matches()) {
                continue;
            }
            MethodNode clinit = cn.methods.stream().filter(m -> m.name.equals("<clinit>")).findFirst().orElse(null);
            if (clinit == null) {
                continue;
            }
            Set<String> assigned = new LinkedHashSet<>();
            for (AbstractInsnNode ain : clinit.instructions) {
                if (ain.getOpcode() == PUTSTATIC) {
                    FieldInsnNode fin = (FieldInsnNode) ain;
                    if (fin.owner.equals(cn.name) && (fin.desc.equals("Ljava/lang/String;") || fin.desc.equals("[Ljava/lang/String;"))
                            && !writtenOutsideClinit.contains(fin.owner + "." + fin.name)) {
                        assigned.add(fin.name);
                    }
                }
            }
            if (assigned.isEmpty()) {
                continue;
            }
            for (String field : assigned) {
                FieldNode fn = cn.fields.stream().filter(f -> f.name.equals(field)).findFirst().orElse(null);
                if (fn == null || (fn.access & ACC_STATIC) == 0) {
                    continue;
                }
                try {
                    Object value = sandbox.getStatic(cn.name, field);
                    if (value instanceof String || value instanceof String[]) {
                        values.put(cn.name + "." + field, value);
                    }
                } catch (IOException e) {
                    failed++;
                    logger.debug("Could not read {}.{}: {}", cn.name, field, e.getMessage());
                }
            }
        }
        if (values.isEmpty()) {
            return;
        }

        for (ClassNode cn : classNodes()) {
            for (MethodNode mn : cn.methods) {
                if (mn.name.equals("<clinit>") && values.keySet().stream().anyMatch(k -> k.startsWith(cn.name + "."))) {
                    continue; // keep the initialiser intact; the fields still exist
                }
                for (AbstractInsnNode ain = mn.instructions.getFirst(); ain != null; ain = ain.getNext()) {
                    if (ain.getOpcode() != GETSTATIC) {
                        continue;
                    }
                    FieldInsnNode fin = (FieldInsnNode) ain;
                    Object value = values.get(fin.owner + "." + fin.name);
                    if (value instanceof String) {
                        LdcInsnNode ldc = new LdcInsnNode(value);
                        mn.instructions.set(ain, ldc);
                        ain = ldc;
                        replaced++;
                    } else if (value instanceof String[]) {
                        AbstractInsnNode idx = Utils.getNext(ain);
                        AbstractInsnNode load = idx == null ? null : Utils.getNext(idx);
                        if (idx != null && load != null && Utils.isInteger(idx) && load.getOpcode() == AALOAD) {
                            int i = Utils.getIntValue(idx);
                            String[] arr = (String[]) value;
                            if (i >= 0 && i < arr.length && arr[i] != null) {
                                LdcInsnNode ldc = new LdcInsnNode(arr[i]);
                                mn.instructions.remove(idx);
                                mn.instructions.remove(load);
                                mn.instructions.set(ain, ldc);
                                ain = ldc;
                                replaced++;
                            }
                        }
                    }
                }
            }
        }
        logger.info("[SandboxStringTransformer] Resolved {} static string field(s)", values.size());
    }

    // ------------------------------------------------------------------ pattern 2: constant-argument calls

    private void transformMethodCalls(Pattern ownerFilter) {
        Map<String, Object> cache = new HashMap<>();
        Set<String> callerSensitive = new HashSet<>();
        Set<String> notCallerSensitive = new HashSet<>();
        Set<String> trampolinesDefined = new HashSet<>();
        Set<String> trampolinesFailed = new HashSet<>();
        Map<String, Integer> remainingCalls = new HashMap<>();

        for (ClassNode cn : classNodes()) {
            for (MethodNode mn : cn.methods) {
                for (AbstractInsnNode ain = mn.instructions.getFirst(); ain != null; ain = ain.getNext()) {
                    if (ain.getOpcode() != INVOKESTATIC) {
                        continue;
                    }
                    MethodInsnNode min = (MethodInsnNode) ain;
                    ClassNode owner = classes.get(min.owner);
                    if (owner == null || !Type.getReturnType(min.desc).getDescriptor().equals("Ljava/lang/String;")) {
                        continue;
                    }
                    if (ownerFilter != null && !ownerFilter.matcher(min.owner).matches()) {
                        continue;
                    }
                    Type[] argTypes = Type.getArgumentTypes(min.desc);
                    if (argTypes.length > getConfig().getMaxArgs()) {
                        continue;
                    }
                    MethodNode target = owner.methods.stream().filter(m -> m.name.equals(min.name) && m.desc.equals(min.desc)).findFirst().orElse(null);
                    if (target == null || (target.access & ACC_STATIC) == 0) {
                        continue;
                    }
                    String key = min.owner + "." + min.name + min.desc;
                    remainingCalls.merge(key, 1, Integer::sum);

                    Object[] args = new Object[argTypes.length];
                    List<AbstractInsnNode> argInsns = new ArrayList<>();
                    if (!collectConstantArgs(ain, argTypes, args, argInsns)) {
                        continue;
                    }

                    boolean sensitive;
                    if (callerSensitive.contains(key)) {
                        sensitive = true;
                    } else if (notCallerSensitive.contains(key)) {
                        sensitive = false;
                    } else {
                        sensitive = isCallerSensitive(owner, target, new HashSet<>());
                        (sensitive ? callerSensitive : notCallerSensitive).add(key);
                    }

                    String cacheKey = (sensitive ? cn.name + "#" + mn.name + "|" : "") + key + Arrays.toString(args);
                    Object result;
                    if (cache.containsKey(cacheKey)) {
                        result = cache.get(cacheKey);
                    } else {
                        result = invoke(min, args, sensitive, cn, mn, trampolinesDefined, trampolinesFailed);
                        cache.put(cacheKey, result);
                    }
                    if (!(result instanceof String)) {
                        failed++;
                        continue;
                    }
                    for (AbstractInsnNode argInsn : argInsns) {
                        mn.instructions.remove(argInsn);
                    }
                    LdcInsnNode ldc = new LdcInsnNode(result);
                    mn.instructions.set(ain, ldc);
                    ain = ldc;
                    replaced++;
                    remainingCalls.merge(key, -1, Integer::sum);
                }
            }
        }

        if (getConfig().isRemoveDecryptors()) {
            int removed = 0;
            for (Map.Entry<String, Integer> e : remainingCalls.entrySet()) {
                if (e.getValue() != 0) {
                    continue;
                }
                String key = e.getKey();
                String ownerName = key.substring(0, key.indexOf('.'));
                String name = key.substring(key.indexOf('.') + 1, key.indexOf('('));
                String desc = key.substring(key.indexOf('('));
                ClassNode owner = classes.get(ownerName);
                if (owner != null && !isReferenced(ownerName, name, desc)) {
                    if (owner.methods.removeIf(m -> m.name.equals(name) && m.desc.equals(desc) && (m.access & ACC_STATIC) != 0)) {
                        removed++;
                    }
                }
            }
            logger.info("[SandboxStringTransformer] Removed {} unreferenced decryptor method(s)", removed);
        }
    }

    private Object invoke(MethodInsnNode min, Object[] args, boolean sensitive, ClassNode caller, MethodNode callerMethod,
                          Set<String> trampolinesDefined, Set<String> trampolinesFailed) {
        try {
            if (sensitive && !trampolinesFailed.contains(caller.name)) {
                String trampolineMethod = callerMethod.name.startsWith("<") ? "call" : callerMethod.name;
                String trampolineKey = caller.name + "#" + trampolineMethod + min.desc;
                if (!trampolinesDefined.contains(trampolineKey)) {
                    try {
                        // One trampoline class per caller class, named exactly like it so that stack-walking
                        // decryptors see the expected caller. Only possible while the real class is not loaded.
                        sandbox.defineClass(caller.name, trampoline(caller.name, trampolineMethod, min));
                        trampolinesDefined.add(trampolineKey);
                    } catch (IOException e) {
                        trampolinesFailed.add(caller.name);
                        logger.debug("Trampoline for {} not possible ({}), calling directly", caller.name, e.getMessage());
                    }
                }
                if (trampolinesDefined.contains(trampolineKey)) {
                    return sandbox.invokeStatic(caller.name, trampolineMethod, min.desc, args);
                }
            }
            return sandbox.invokeStatic(min.owner, min.name, min.desc, args);
        } catch (IOException e) {
            logger.debug("Could not execute {}.{}{} {}: {}", min.owner, min.name, min.desc, Arrays.toString(args), e.getMessage());
            return null;
        }
    }

    /**
     * Generates {@code public class <caller> { public static String <method>(<desc args>) { return owner.name(args); } }}.
     * When a trampoline for the same caller already exists this defines a second class of the same name, which the
     * guest loader rejects; callers therefore track success per caller+method key and fall back to direct calls.
     */
    private static byte[] trampoline(String callerName, String methodName, MethodInsnNode target) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(V11, ACC_PUBLIC | ACC_SUPER, callerName, null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, methodName, target.desc, null, null);
        mv.visitCode();
        int slot = 0;
        for (Type t : Type.getArgumentTypes(target.desc)) {
            mv.visitVarInsn(t.getOpcode(ILOAD), slot);
            slot += t.getSize();
        }
        mv.visitMethodInsn(INVOKESTATIC, target.owner, target.name, target.desc, false);
        mv.visitInsn(ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private boolean collectConstantArgs(AbstractInsnNode call, Type[] argTypes, Object[] args, List<AbstractInsnNode> argInsns) {
        AbstractInsnNode cur = call;
        for (int i = argTypes.length - 1; i >= 0; i--) {
            cur = Utils.getPrevious(cur);
            if (cur == null) {
                return false;
            }
            Type t = argTypes[i];
            switch (t.getSort()) {
                case Type.INT:
                case Type.SHORT:
                case Type.BYTE:
                case Type.CHAR:
                case Type.BOOLEAN:
                    if (!Utils.isInteger(cur)) {
                        return false;
                    }
                    args[i] = Utils.getIntValue(cur);
                    break;
                case Type.LONG:
                    if (!Utils.isLong(cur)) {
                        return false;
                    }
                    args[i] = Utils.getLongValue(cur);
                    break;
                case Type.OBJECT:
                    if (!t.getDescriptor().equals("Ljava/lang/String;")) {
                        return false;
                    }
                    if (cur.getOpcode() == ACONST_NULL) {
                        args[i] = null;
                    } else if (cur.getOpcode() == LDC && ((LdcInsnNode) cur).cst instanceof String) {
                        args[i] = ((LdcInsnNode) cur).cst;
                    } else {
                        return false;
                    }
                    break;
                default:
                    return false;
            }
            argInsns.add(cur);
        }
        return true;
    }

    private boolean isCallerSensitive(ClassNode owner, MethodNode method, Set<String> visited) {
        if (!visited.add(owner.name + "." + method.name + method.desc) || visited.size() > 16) {
            return false;
        }
        for (AbstractInsnNode ain : method.instructions) {
            if (ain instanceof MethodInsnNode) {
                MethodInsnNode min = (MethodInsnNode) ain;
                if (CALLER_SENSITIVE_MARKERS.contains(min.name) || min.owner.equals("java/lang/StackWalker")) {
                    return true;
                }
                ClassNode callee = classes.get(min.owner);
                if (callee != null) {
                    MethodNode target = callee.methods.stream().filter(m -> m.name.equals(min.name) && m.desc.equals(min.desc)).findFirst().orElse(null);
                    if (target != null && isCallerSensitive(callee, target, visited)) {
                        return true;
                    }
                }
            } else if (ain instanceof LdcInsnNode && ((LdcInsnNode) ain).cst instanceof Type) {
                return true; // class literals are often used to derive keys from the caller
            }
        }
        return false;
    }

    private boolean isReferenced(String owner, String name, String desc) {
        for (ClassNode cn : classNodes()) {
            for (MethodNode mn : cn.methods) {
                for (AbstractInsnNode ain : mn.instructions) {
                    if (ain instanceof MethodInsnNode) {
                        MethodInsnNode min = (MethodInsnNode) ain;
                        if (min.owner.equals(owner) && min.name.equals(name) && min.desc.equals(desc)) {
                            return true;
                        }
                    } else if (ain instanceof LdcInsnNode && ((LdcInsnNode) ain).cst instanceof org.objectweb.asm.Handle) {
                        org.objectweb.asm.Handle h = (org.objectweb.asm.Handle) ((LdcInsnNode) ain).cst;
                        if (h.getOwner().equals(owner) && h.getName().equals(name) && h.getDesc().equals(desc)) {
                            return true;
                        }
                    } else if (ain instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode) {
                        for (Object arg : ((org.objectweb.asm.tree.InvokeDynamicInsnNode) ain).bsmArgs) {
                            if (arg instanceof org.objectweb.asm.Handle) {
                                org.objectweb.asm.Handle h = (org.objectweb.asm.Handle) arg;
                                if (h.getOwner().equals(owner) && h.getName().equals(name) && h.getDesc().equals(desc)) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public static class Config extends TransformerConfig {
        private boolean dryRun = false;
        private boolean staticFields = true;
        private boolean methodCalls = true;
        private boolean removeDecryptors = true;
        private int maxArgs = 6;
        private long timeoutMillis = 10_000;
        private int maxHeapMb = 512;
        private String java;
        private String ownerFilter;
        private List<String> jvmArgs;
        private List<File> extraClasspath;

        public Config() {
            super(SandboxStringTransformer.class);
        }

        /**
         * When {@code true}, only report how many static-field pools and decrypt call sites would be resolved
         * (see the log output); the sandbox is never started, the input's code never runs and no class is
         * modified. Use this to gauge coverage on inputs you are not ready to (or should not) actually execute.
         */
        public boolean isDryRun() {
            return dryRun;
        }

        public void setDryRun(boolean dryRun) {
            this.dryRun = dryRun;
        }

        public boolean isStaticFields() {
            return staticFields;
        }

        public void setStaticFields(boolean staticFields) {
            this.staticFields = staticFields;
        }

        public boolean isMethodCalls() {
            return methodCalls;
        }

        public void setMethodCalls(boolean methodCalls) {
            this.methodCalls = methodCalls;
        }

        public boolean isRemoveDecryptors() {
            return removeDecryptors;
        }

        public void setRemoveDecryptors(boolean removeDecryptors) {
            this.removeDecryptors = removeDecryptors;
        }

        public int getMaxArgs() {
            return maxArgs;
        }

        public void setMaxArgs(int maxArgs) {
            this.maxArgs = maxArgs;
        }

        public long getTimeoutMillis() {
            return timeoutMillis;
        }

        public void setTimeoutMillis(long timeoutMillis) {
            this.timeoutMillis = timeoutMillis;
        }

        public int getMaxHeapMb() {
            return maxHeapMb;
        }

        public void setMaxHeapMb(int maxHeapMb) {
            this.maxHeapMb = maxHeapMb;
        }

        /** Path to the {@code java} executable used for the sandbox; defaults to the running JVM. */
        public String getJava() {
            return java;
        }

        public void setJava(String java) {
            this.java = java;
        }

        /** Regex on internal class names; only decryptors/fields declared in matching classes are executed. */
        public String getOwnerFilter() {
            return ownerFilter;
        }

        public void setOwnerFilter(String ownerFilter) {
            this.ownerFilter = ownerFilter;
        }

        public List<String> getJvmArgs() {
            return jvmArgs;
        }

        public void setJvmArgs(List<String> jvmArgs) {
            this.jvmArgs = jvmArgs;
        }

        public List<File> getExtraClasspath() {
            return extraClasspath;
        }

        public void setExtraClasspath(List<File> extraClasspath) {
            this.extraClasspath = extraClasspath;
        }
    }
}
