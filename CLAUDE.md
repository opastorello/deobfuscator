# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Maintained fork of `java-deobfuscator/deobfuscator` (upstream abandoned). A CLI/library that reverses commercial
Java obfuscators (Zelix, Stringer, Allatori, DashO, ...) by loading a jar into ASM `ClassNode`s, running a list of
transformers, and writing the result. Bytecode target is Java 11 (`maven.compiler.release`), runs on JDK 11–25,
reads class files up to the newest Java release (ASM 9.8).

## Build / test / run

No system Maven is required — use the wrapper (`mvnw.cmd` on Windows, `./mvnw` elsewhere):

```
./mvnw package                     # build + tests → target/deobfuscator-1.0.0.jar (shaded, runnable)
./mvnw -DskipTests package
./mvnw test -Dtest=SandboxStringTransformerTest      # single test class
java -jar target/deobfuscator-1.0.0.jar -config config.yml
```

- Tests are JUnit 4. `TestRunner` only does real work when `src/test/resources/Krakatau` exists (it doesn't by default);
  `SandboxStringTransformerTest` compiles a sample with the running JDK into `target/sandbox-test/` and is the
  end-to-end check for the sandbox.
- Surefire and the manifest already carry the `--add-opens` flags the reflection code needs; don't drop them.
- Inputs are held entirely in memory; large jars need `-Xmx` of several GB. On this machine keep `-Xmx` bounded
  (see memory notes) — JVM crashes with `errno=1455` are the host's commit limit, not a bug.
- `javavm` (dependency used by the legacy emulation transformers) is built by JitPack from
  `github.com/java-deobfuscator/javavm`, pinned by commit hash in `version.javavm`. The original samczsun repo is dead.

## Architecture

Pipeline (`Deobfuscator.start()`): `loadClasspath()` → `loadInput()` → optional detection (`rules/`) →
`runFromConfig()` for each `TransformerConfig` → write. Config is YAML deserialized into `config/Configuration`;
each list entry under `transformers:` is either a class id string (relative to
`com.javadeobfuscator.deobfuscator.transformers.`) or a one-key map `{id: {options}}` handled by
`TransformerConfigDeserializer`. Transformers with options declare
`@TransformerConfig.ConfigOptions(configClass = X.Config.class)` and a `Config extends TransformerConfig` bean.

Three class maps matter everywhere: `classes` (the input, mutated and written back), `classpath`
(`-path`: hierarchy/signatures only, loaded with `SKIP_CODE`), `libraries` (`-libraries`: full code, fed to
`javavm`). When nothing on `path` provides `java/lang/Object`, the running JDK's `java.*` modules are loaded via
`jrt:/` (`Configuration.loadRuntime` / `runtimeModules`); classes still missing are pulled lazily from the running
JVM in `pullFromRuntime`. `path`/`libraries` entries may be jars, `.jmod`s, directories of jars, or a JDK home (8 or 9+).

Transformers (`transformers/<obfuscator>/...`) extend `Transformer<T>` and implement `boolean transform()`
(returns whether anything changed; `WrongTransformerException` means "doesn't apply"). `classNodes()` iterates the
input. Three ways to evaluate obfuscated code exist — pick deliberately:

1. **`executor/MethodExecutor`** – in-process symbolic/concrete interpreter over `ClassNode`s. Behaviour is supplied by
   `Provider`s (`DelegatingProvider` + `JVMMethodProvider` for whitelisted JDK methods, `MappedMethodProvider`
   for input methods, `ReflectiveProvider` for real reflection). Cheap, safe, limited.
2. **`javavm`** via `TransformerHelper.newVirtualMachine()` – full JVM emulation but **Java 8 only**: needs an
   `rt.jar` located through `-Ddeobfuscator.jre8` / `DEOBFUSCATOR_JRE8`. Used by the Stringer/Zelix/Allatori/DashO
   string transformers. Cannot run modern inputs (records, indy string concat, ...).
3. **`sandbox/`** (`SandboxExecutor` ↔ `SandboxAgent`) – spawns an isolated child JVM (same JDK as the tool) that
   loads the input jar in its own class loader; JSON-lines over stdin/stdout (`SandboxProtocol`), per-call timeout,
   auto-restart, `SecurityManager` on JDK ≤ 23. The untrusted code really runs. `general.SandboxStringTransformer`
   is the reference user (static-field pools, constant-arg `INVOKESTATIC` decryptors, caller-sensitive decryptors via
   a trampoline class named after the caller). New transformers for modern obfuscators should build on this rather
   than on `javavm`.

Supporting pieces: `matcher/InstructionPattern` (declarative bytecode pattern matching used by most transformers,
see CUSTOMTRANSFORMER.md), `analyzer/MethodAnalyzer` (stack/frame analysis), `rules/` (detectors reported by
`detect: true`, each `Rule.test()` returns a recommendation string or null), `utils/Utils` (constant-instruction
helpers such as `isInteger`/`getIntValue`, `classForType`, hex/Unsafe helpers).

## Conventions

- Don't reintroduce JDK-internal APIs (`sun.invoke.util`, `javax.xml.bind`, `Unsafe` constructor); the code was
  cleaned of them to run on 11+. `sun.misc.Unsafe` via `theUnsafe` is the one allowed exception.
- ASM API level is `ASM9`; class-file support comes from the ASM version in `pom.xml` (`version.asm`).
- Never run transformers against third-party commercial jars in this repo's tests; fixtures are generated in-test.
- CI: `pr.yml` builds on JDK 11/17/21/22/25; a push to `master` builds on 17 and republishes the `latest` release.
- `commonerrors/*.md` document per-obfuscator pitfalls; update them when a transformer's behaviour changes.
