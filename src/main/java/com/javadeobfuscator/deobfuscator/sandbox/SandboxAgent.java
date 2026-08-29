package com.javadeobfuscator.deobfuscator.sandbox;

import com.google.gson.Gson;
import com.javadeobfuscator.deobfuscator.sandbox.SandboxProtocol.Request;
import com.javadeobfuscator.deobfuscator.sandbox.SandboxProtocol.Response;
import com.javadeobfuscator.deobfuscator.sandbox.SandboxProtocol.Value;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.security.Permission;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Entry point of the sandbox child process. Loads the input jar (plus libraries) into an isolated class loader on
 * the <em>real</em> JVM and executes requests coming from {@link SandboxExecutor} over stdin/stdout.
 * <p>
 * Because the untrusted, obfuscated code is really executed here, the parent starts this process with a private
 * temporary working directory/home, no inherited stdin data, a heap cap and a per-request timeout, and the agent
 * installs a restrictive {@link SecurityManager} where the JDK still allows it (JDK 11-23). On JDK 24+ the
 * security manager is gone; the process boundary remains the isolation.
 */
public final class SandboxAgent {
    private static final Gson GSON = new Gson();

    private final SandboxClassLoader loader;

    private SandboxAgent(List<URL> urls) {
        this.loader = new SandboxClassLoader(urls.toArray(new URL[0]));
    }

    public static void main(String[] args) throws Exception {
        // Everything printed by the loaded code must not corrupt the protocol channel: keep the real stdout
        // for ourselves, redirect System.out/err of the guest to stderr.
        PrintStream channel = new PrintStream(new FileOutputStream(FileDescriptor.out), true, "UTF-8");
        PrintStream err = new PrintStream(new FileOutputStream(FileDescriptor.err), true, "UTF-8");
        System.setOut(err);
        System.setErr(err);

        List<URL> urls = new ArrayList<>();
        for (String arg : args) {
            urls.add(new File(arg).toURI().toURL());
        }
        SandboxAgent agent = new SandboxAgent(urls);
        installSecurityManager(err);

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isEmpty()) {
                continue;
            }
            Request request;
            try {
                request = GSON.fromJson(line, Request.class);
            } catch (RuntimeException e) {
                continue;
            }
            Response response = new Response();
            response.id = request.id;
            try {
                if (SandboxProtocol.OP_SHUTDOWN.equals(request.op)) {
                    response.ok = true;
                    channel.println(GSON.toJson(response));
                    channel.flush();
                    Runtime.getRuntime().halt(0);
                }
                response.value = Value.of(agent.handle(request));
                response.ok = true;
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause() == null ? e : e.getCause();
                response.ok = false;
                response.errorType = cause.getClass().getName();
                response.error = String.valueOf(cause.getMessage());
            } catch (Throwable t) {
                response.ok = false;
                response.errorType = t.getClass().getName();
                response.error = String.valueOf(t.getMessage());
            }
            channel.println(GSON.toJson(response));
            channel.flush();
        }
        Runtime.getRuntime().halt(0);
    }

    private Object handle(Request request) throws Throwable {
        switch (request.op) {
            case SandboxProtocol.OP_PING:
                return "pong " + Runtime.version();
            case SandboxProtocol.OP_INIT_CLASS:
                Class.forName(request.owner.replace('/', '.'), true, loader);
                return null;
            case SandboxProtocol.OP_DEFINE_CLASS:
                loader.define(request.owner.replace('/', '.'), Base64.getDecoder().decode(request.bytes));
                return null;
            case SandboxProtocol.OP_GET_STATIC: {
                Class<?> clazz = Class.forName(request.owner.replace('/', '.'), true, loader);
                Field field = findField(clazz, request.name);
                field.setAccessible(true);
                return field.get(null);
            }
            case SandboxProtocol.OP_INVOKE_STATIC: {
                Class<?> clazz = Class.forName(request.owner.replace('/', '.'), true, loader);
                Method method = findMethod(clazz, request.name, request.desc);
                if (!Modifier.isStatic(method.getModifiers())) {
                    throw new IllegalArgumentException("not static: " + request.owner + "." + request.name + request.desc);
                }
                method.setAccessible(true);
                Object[] args = new Object[request.args == null ? 0 : request.args.size()];
                for (int i = 0; i < args.length; i++) {
                    args[i] = coerce(request.args.get(i).toObject(), method.getParameterTypes()[i]);
                }
                return method.invoke(null, args);
            }
            default:
                throw new IllegalArgumentException("unknown op " + request.op);
        }
    }

    private static Object coerce(Object value, Class<?> target) {
        if (value == null || !(value instanceof Number)) {
            return value;
        }
        Number n = (Number) value;
        if (target == int.class || target == Integer.class) return n.intValue();
        if (target == long.class || target == Long.class) return n.longValue();
        if (target == short.class || target == Short.class) return n.shortValue();
        if (target == byte.class || target == Byte.class) return n.byteValue();
        if (target == char.class || target == Character.class) return (char) n.intValue();
        if (target == boolean.class || target == Boolean.class) return n.intValue() != 0;
        if (target == float.class || target == Float.class) return n.floatValue();
        if (target == double.class || target == Double.class) return n.doubleValue();
        return value;
    }

    private static Field findField(Class<?> clazz, String name) throws NoSuchFieldException {
        for (Class<?> c = clazz; c != null; c = c.getSuperclass()) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
            }
        }
        throw new NoSuchFieldException(clazz.getName() + "." + name);
    }

    private static Method findMethod(Class<?> clazz, String name, String desc) throws NoSuchMethodException {
        for (Class<?> c = clazz; c != null; c = c.getSuperclass()) {
            for (Method m : c.getDeclaredMethods()) {
                if (m.getName().equals(name) && descriptorOf(m).equals(desc)) {
                    return m;
                }
            }
        }
        throw new NoSuchMethodException(clazz.getName() + "." + name + desc);
    }

    private static String descriptorOf(Method m) {
        StringBuilder sb = new StringBuilder("(");
        for (Class<?> p : m.getParameterTypes()) {
            sb.append(descriptorOf(p));
        }
        return sb.append(')').append(descriptorOf(m.getReturnType())).toString();
    }

    private static String descriptorOf(Class<?> c) {
        if (c.isArray()) {
            return c.getName().replace('.', '/');
        }
        if (c.isPrimitive()) {
            if (c == int.class) return "I";
            if (c == long.class) return "J";
            if (c == boolean.class) return "Z";
            if (c == byte.class) return "B";
            if (c == char.class) return "C";
            if (c == short.class) return "S";
            if (c == float.class) return "F";
            if (c == double.class) return "D";
            return "V";
        }
        return "L" + c.getName().replace('.', '/') + ";";
    }

    @SuppressWarnings("removal")
    private static void installSecurityManager(PrintStream err) {
        if (Runtime.version().feature() >= 24) {
            err.println("[sandbox] SecurityManager is not available on Java " + Runtime.version().feature()
                    + "; relying on process isolation only");
            return;
        }
        try {
            System.setSecurityManager(new SecurityManager() {
                @Override
                public void checkPermission(Permission perm) {
                    String name = perm.getName();
                    String type = perm.getClass().getName();
                    if (perm instanceof RuntimePermission) {
                        if (name.startsWith("exitVM") || name.equals("setSecurityManager") || name.equals("shutdownHooks")) {
                            throw new SecurityException("sandbox: " + name);
                        }
                        return;
                    }
                    if (perm instanceof java.io.FilePermission) {
                        String actions = perm.getActions();
                        if (actions.contains("write") || actions.contains("delete") || actions.contains("execute")) {
                            throw new SecurityException("sandbox: file " + actions + " " + name);
                        }
                        return;
                    }
                    if (type.startsWith("java.net.") || type.startsWith("javax.net.") || type.equals("java.net.SocketPermission")) {
                        throw new SecurityException("sandbox: network " + name);
                    }
                }

                @Override
                public void checkPermission(Permission perm, Object context) {
                    checkPermission(perm);
                }

                @Override
                public void checkExec(String cmd) {
                    throw new SecurityException("sandbox: exec " + cmd);
                }

                @Override
                public void checkExit(int status) {
                    throw new SecurityException("sandbox: exit " + status);
                }
            });
        } catch (UnsupportedOperationException | SecurityException e) {
            err.println("[sandbox] could not install SecurityManager: " + e);
        }
    }

    /** Isolated loader: guest classes never see the deobfuscator's own classpath. */
    private static final class SandboxClassLoader extends URLClassLoader {
        SandboxClassLoader(URL[] urls) {
            super(urls, ClassLoader.getPlatformClassLoader());
        }

        void define(String name, byte[] bytes) {
            defineClass(name, bytes, 0, bytes.length);
        }
    }
}
