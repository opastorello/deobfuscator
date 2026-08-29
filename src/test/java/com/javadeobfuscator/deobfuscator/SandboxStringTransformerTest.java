package com.javadeobfuscator.deobfuscator;

import com.javadeobfuscator.deobfuscator.config.Configuration;
import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import com.javadeobfuscator.deobfuscator.transformers.general.SandboxStringTransformer;
import org.junit.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import java.util.zip.ZipFile;

import static org.junit.Assert.*;

/**
 * Builds a small "obfuscated" jar with the current JDK (so it carries the newest class-file version) and checks
 * that {@link SandboxStringTransformer} resolves all three decryption styles by really executing them.
 */
public class SandboxStringTransformerTest {

    private static final String DECRYPT = ""
            + "package sample;\n"
            + "public class Decrypt {\n"
            + "    private static final byte[] TABLE = \"hello sandbox|second string|third\".getBytes();\n"
            + "    // Zelix-style (II)String: offset/length into a table, xor'ed with a key\n"
            + "    public static String d(int off, int len) {\n"
            + "        char[] out = new char[len];\n"
            + "        for (int i = 0; i < len; i++) out[i] = (char) (TABLE[off + i] ^ 0);\n"
            + "        return new String(out);\n"
            + "    }\n"
            + "    // Allatori-style (String)String\n"
            + "    public static String a(String s) {\n"
            + "        StringBuilder sb = new StringBuilder();\n"
            + "        for (int i = 0; i < s.length(); i++) sb.append((char) (s.charAt(i) ^ 0x2A));\n"
            + "        return sb.toString();\n"
            + "    }\n"
            + "    // caller-sensitive: key derived from the caller class name\n"
            + "    public static String cs(int shift) {\n"
            + "        String caller = new Throwable().getStackTrace()[1].getClassName();\n"
            + "        int key = caller.hashCode() & 0xF;\n"
            + "        return \"caller\" + caller.length() + \":\" + (key + shift);\n"
            + "    }\n"
            + "}\n";

    private static final String POOL = ""
            + "package sample;\n"
            + "public class Pool {\n"
            + "    public static final String[] P;\n"
            + "    public static String S;\n"
            + "    static {\n"
            + "        P = new String[] { Decrypt.d(0, 5), Decrypt.a(Decrypt.a(\"pooled\")) };\n"
            + "        S = Decrypt.d(6, 7);\n"
            + "    }\n"
            + "}\n";

    private static final String MAIN = ""
            + "package sample;\n"
            + "public class Main {\n"
            + "    RECORD_DECL\n"
            + "    public static void main(String[] args) {\n"
            + "        String x = Decrypt.d(0, 13);\n"
            + "        String y = Decrypt.a(Decrypt.a(\"allatori\"));\n"
            + "        String z = Pool.P[1] + Pool.S;\n"
            + "        String w = Decrypt.cs(1);\n"
            + "        System.out.println(new R(x + y + z + w, 1));\n"
            + "    }\n"
            + "}\n";

    @Test
    public void resolvesStringsByExecutingThem() throws Throwable {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull("test needs a JDK", compiler);
        Path work = java.nio.file.Paths.get("target", "sandbox-test");
        if (Files.exists(work)) {
            try (Stream<Path> old = Files.walk(work)) {
                old.sorted(java.util.Comparator.reverseOrder()).forEach(q -> q.toFile().delete());
            }
        }
        Files.createDirectories(work);
        Path src = work.resolve("src/sample");
        Files.createDirectories(src);
        Files.write(src.resolve("Decrypt.java"), DECRYPT.getBytes(StandardCharsets.UTF_8));
        Files.write(src.resolve("Pool.java"), POOL.getBytes(StandardCharsets.UTF_8));
        // records need javac 16+; on older JDKs the sample uses a plain class with the same toString()
        boolean records = Runtime.version().feature() >= 16;
        String mainSource = MAIN.replace("RECORD_DECL", records
                ? "record R(String a, int b) {}"
                : "static class R { final String a; final int b; R(String a, int b) { this.a = a; this.b = b; } public String toString() { return \"R[a=\" + a + \", b=\" + b + \"]\"; } }");
        Files.write(src.resolve("Main.java"), mainSource.getBytes(StandardCharsets.UTF_8));
        Path classes = Files.createDirectories(work.resolve("classes"));
        int rc = compiler.run(null, null, null, "-d", classes.toString(),
                src.resolve("Decrypt.java").toString(), src.resolve("Pool.java").toString(), src.resolve("Main.java").toString());
        assertEquals("javac failed", 0, rc);

        File input = work.resolve("input.jar").toFile();
        try (JarOutputStream jar = new JarOutputStream(new FileOutputStream(input)); Stream<Path> files = Files.walk(classes)) {
            for (Path p : (Iterable<Path>) files.filter(Files::isRegularFile)::iterator) {
                jar.putNextEntry(new JarEntry(classes.relativize(p).toString().replace('\\', '/')));
                jar.write(Files.readAllBytes(p));
                jar.closeEntry();
            }
        }
        File output = work.resolve("output.jar").toFile();

        Configuration config = new Configuration();
        config.setInput(input);
        config.setOutput(output);
        config.setTransformers(Collections.singletonList(TransformerConfig.configFor(SandboxStringTransformer.class)));
        new Deobfuscator(config).start();
        assertTrue(output.isFile());

        ClassNode main = read(output, "sample/Main.class");
        MethodNode mainMethod = main.methods.stream().filter(m -> m.name.equals("main")).findFirst().orElseThrow(AssertionError::new);
        List<String> ldcs = new ArrayList<>();
        List<String> calls = new ArrayList<>();
        for (AbstractInsnNode ain : mainMethod.instructions) {
            if (ain instanceof LdcInsnNode && ((LdcInsnNode) ain).cst instanceof String) {
                ldcs.add((String) ((LdcInsnNode) ain).cst);
            } else if (ain instanceof MethodInsnNode) {
                MethodInsnNode min = (MethodInsnNode) ain;
                calls.add(min.owner + "." + min.name);
            }
        }
        assertTrue("(II)String call resolved: " + ldcs, ldcs.contains("hello sandbox"));
        assertTrue("(String)String nested call resolved: " + ldcs, ldcs.contains("allatori"));
        assertTrue("static String[] pool resolved: " + ldcs, ldcs.contains("pooled"));
        assertTrue("static String field resolved: " + ldcs, ldcs.contains("sandbox"));
        int expectedKey = "sample.Main".hashCode() & 0xF;
        assertTrue("caller-sensitive call resolved with the caller's identity: " + ldcs, ldcs.contains("caller11:" + (expectedKey + 1)));
        assertFalse("decrypt calls remain: " + calls, calls.stream().anyMatch(c -> c.startsWith("sample/Decrypt.")));

        ClassNode decrypt = read(output, "sample/Decrypt.class");
        assertTrue("unreferenced decryptor removed", decrypt.methods.stream().noneMatch(m -> m.name.equals("cs")));
    }

    private static ClassNode read(File jar, String entry) throws IOException {
        try (ZipFile zip = new ZipFile(jar)) {
            ClassNode node = new ClassNode();
            new ClassReader(zip.getInputStream(zip.getEntry(entry))).accept(node, 0);
            return node;
        }
    }
}
