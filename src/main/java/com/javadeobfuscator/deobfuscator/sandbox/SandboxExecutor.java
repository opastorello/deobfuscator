package com.javadeobfuscator.deobfuscator.sandbox;

import com.google.gson.Gson;
import com.javadeobfuscator.deobfuscator.sandbox.SandboxProtocol.Request;
import com.javadeobfuscator.deobfuscator.sandbox.SandboxProtocol.Response;
import com.javadeobfuscator.deobfuscator.sandbox.SandboxProtocol.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runs code from the input jar inside a separate, isolated JVM process (see {@link SandboxAgent}) and exposes
 * static method invocation / static field reads to transformers. Unlike the embedded {@code javavm}, this uses
 * the real JVM that runs the deobfuscator, so it supports every class-file version and library the JVM supports
 * (records, sealed classes, {@code invokedynamic} string concatenation, {@code MethodHandles}, ...).
 * <p>
 * The child is restarted automatically when it crashes or a request exceeds the timeout.
 */
public final class SandboxExecutor implements Closeable {
    private static final Logger logger = LoggerFactory.getLogger(SandboxExecutor.class);
    private static final Gson GSON = new Gson();

    private final List<File> classpath;
    private final String javaExecutable;
    private final long timeoutMillis;
    private final int maxHeapMb;
    private final List<String> extraJvmArgs;
    private final AtomicLong ids = new AtomicLong();
    private final ExecutorService reader = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "sandbox-reader");
        t.setDaemon(true);
        return t;
    });

    private Process process;
    private Writer stdin;
    private BufferedReader stdout;
    private Path workDir;
    private int restarts;
    private String startupFailure;

    public SandboxExecutor(List<File> classpath, String javaExecutable, long timeoutMillis, int maxHeapMb, List<String> extraJvmArgs) {
        this.classpath = new ArrayList<>(classpath);
        this.javaExecutable = javaExecutable == null || javaExecutable.isEmpty() ? currentJava() : javaExecutable;
        this.timeoutMillis = timeoutMillis <= 0 ? 10_000 : timeoutMillis;
        this.maxHeapMb = maxHeapMb <= 0 ? 512 : maxHeapMb;
        this.extraJvmArgs = extraJvmArgs == null ? Collections.emptyList() : new ArrayList<>(extraJvmArgs);
    }

    public static String currentJava() {
        return ProcessHandle.current().info().command()
                .orElse(System.getProperty("java.home") + File.separator + "bin" + File.separator + "java");
    }

    /** Location of our own classes (shaded jar, or the classpath when running from an IDE/Maven). */
    private static String agentClasspath() {
        try {
            File self = new File(SandboxAgent.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (self.isFile()) {
                return self.getAbsolutePath();
            }
        } catch (Exception ignored) {
        }
        return System.getProperty("java.class.path");
    }

    private synchronized void ensureStarted() throws IOException {
        if (process != null && process.isAlive()) {
            return;
        }
        if (startupFailure != null) {
            throw new SandboxException("SandboxUnavailable", startupFailure);
        }
        if (workDir == null) {
            workDir = Files.createTempDirectory("deobfuscator-sandbox");
            workDir.toFile().deleteOnExit();
        }
        int feature = Runtime.version().feature();
        List<String> cmd = new ArrayList<>();
        cmd.add(javaExecutable);
        cmd.add("-Xms16m");
        cmd.add("-Xmx" + maxHeapMb + "m");
        cmd.add("-XX:MaxMetaspaceSize=256m");
        cmd.add("-XX:ReservedCodeCacheSize=48m");
        cmd.add("-XX:TieredStopAtLevel=1");
        cmd.add("-Xss4m");
        cmd.add("-XX:+UseSerialGC");
        cmd.add("-Djava.awt.headless=true");
        cmd.add("-Duser.home=" + workDir);
        cmd.add("-Djava.io.tmpdir=" + workDir);
        cmd.add("-Duser.dir=" + workDir);
        cmd.add("-Dfile.encoding=UTF-8");
        // The input may reference internals; open the usual suspects so reflection inside decryptors works.
        for (String pkg : Arrays.asList("java.lang", "java.lang.reflect", "java.lang.invoke", "java.util", "java.io", "java.nio", "java.security")) {
            cmd.add("--add-opens");
            cmd.add("java.base/" + pkg + "=ALL-UNNAMED");
        }
        if (feature >= 18 && feature < 24) {
            cmd.add("-Djava.security.manager=allow");
        }
        cmd.addAll(extraJvmArgs);
        cmd.add("-cp");
        cmd.add(agentClasspath());
        cmd.add(SandboxAgent.class.getName());
        for (File f : classpath) {
            cmd.add(f.getAbsolutePath());
        }

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(workDir.toFile());
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        process = pb.start();
        stdin = new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8);
        stdout = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        Object pong;
        try {
            pong = call(SandboxProtocol.OP_PING, null, null, null, null, null);
        } catch (IOException e) {
            startupFailure = "sandbox JVM failed to start (" + String.join(" ", cmd) + "): " + e.getMessage();
            logger.error(startupFailure);
            throw e;
        }
        logger.info("Sandbox JVM started ({}), {}", javaExecutable, pong);
    }

    private synchronized Object call(String op, String owner, String name, String desc, List<Value> args, String bytes) throws IOException {
        ensureStarted();
        Request request = new Request();
        request.id = ids.incrementAndGet();
        request.op = op;
        request.owner = owner;
        request.name = name;
        request.desc = desc;
        request.args = args;
        request.bytes = bytes;
        stdin.write(GSON.toJson(request));
        stdin.write('\n');
        stdin.flush();

        Future<String> line = reader.submit(() -> {
            String l;
            while ((l = stdout.readLine()) != null) {
                if (l.startsWith("{")) {
                    return l;
                }
            }
            return null;
        });
        String json;
        try {
            json = line.get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            line.cancel(true);
            kill();
            throw new SandboxException("TimeoutException", "sandbox call timed out after " + timeoutMillis + "ms: " + owner + "." + name + desc);
        } catch (Exception e) {
            kill();
            throw new IOException("sandbox communication failed", e);
        }
        if (json == null) {
            kill();
            throw new SandboxException("EOFException", "sandbox JVM died while executing " + owner + "." + name + desc);
        }
        Response response = GSON.fromJson(json, Response.class);
        if (!response.ok) {
            throw new SandboxException(response.errorType, response.error);
        }
        return response.value == null ? null : response.value.toObject();
    }

    private synchronized void kill() {
        if (process != null) {
            process.destroyForcibly();
            process = null;
            restarts++;
            if (restarts > 50) {
                logger.warn("Sandbox JVM has been restarted {} times; the input is probably fighting the sandbox", restarts);
            }
        }
    }

    /** Runs static initialisation of a class inside the sandbox. */
    public void initClass(String internalName) throws IOException {
        call(SandboxProtocol.OP_INIT_CLASS, internalName, null, null, null, null);
    }

    /** Defines an additional (synthetic) class in the guest class loader. */
    public void defineClass(String internalName, byte[] bytes) throws IOException {
        call(SandboxProtocol.OP_DEFINE_CLASS, internalName, null, null, null, Base64.getEncoder().encodeToString(bytes));
    }

    /** Reads a static field; the class is initialised first. */
    public Object getStatic(String owner, String field) throws IOException {
        return call(SandboxProtocol.OP_GET_STATIC, owner, field, null, null, null);
    }

    /** Invokes a static method with constant arguments (primitives, Strings and primitive/String arrays). */
    public Object invokeStatic(String owner, String name, String desc, Object... args) throws IOException {
        List<Value> values = new ArrayList<>();
        for (Object arg : args) {
            values.add(Value.of(arg));
        }
        return call(SandboxProtocol.OP_INVOKE_STATIC, owner, name, desc, values, null);
    }

    @Override
    public synchronized void close() {
        if (process != null && process.isAlive()) {
            try {
                call(SandboxProtocol.OP_SHUTDOWN, null, null, null, null, null);
            } catch (Exception ignored) {
            }
            process.destroyForcibly();
        }
        process = null;
        reader.shutdownNow();
        if (workDir != null) {
            try {
                Files.walk(workDir).sorted((a, b) -> b.compareTo(a)).forEach(p -> p.toFile().delete());
            } catch (IOException ignored) {
            }
        }
    }

    /** Error raised by code running inside the sandbox (or by the sandbox itself). */
    public static final class SandboxException extends IOException {
        public final String type;

        public SandboxException(String type, String message) {
            super(type + ": " + message);
            this.type = type;
        }
    }
}
