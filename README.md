# Deobfuscator

> **Maintained fork.** The original [java-deobfuscator/deobfuscator](https://github.com/java-deobfuscator/deobfuscator)
> is no longer maintained (last release targets Java 8 and its dependency repository is offline). This fork keeps the
> project alive in 2026: it builds and runs on **JDK 11 through 22+**, uses ASM 9.8 (reads class files up to the latest
> Java release), ships a Maven wrapper, and loads the Java runtime automatically through `jrt:/` (no `rt.jar` required).
> Issues and pull requests are welcome here.

This project aims to deobfuscate most commercially-available obfuscators for Java.

## Updates
To download an updated version of Java Deobfuscator, go to the releases tab.

If you would like to run this program with a GUI, go to https://github.com/java-deobfuscator/deobfuscator-gui and grab a download. Put the deobfuscator-gui.jar in the same folder as deobfuscator.jar.

## Requirements

* **Java 11 or newer** to run (tested on JDK 11, 17, 21, 22 and 25). Class files up to the newest Java release are supported (ASM 9.8).
* No `rt.jar` needed: when the config does not put a Java runtime on `path`, the classes of the JVM running the deobfuscator are loaded automatically through `jrt:/`. You can still point `path` at a JDK home (8 or 9+), a `.jar`, a `.jmod` or a directory of them.
* The transformers that run code inside the embedded `javavm` (Stringer, Zelix enhanced strings, Allatori/DashO strings, BisGuard, ...) still need a **Java 8** runtime image. Pass one with `-Ddeobfuscator.jre8=<path to JDK 8 / JRE 8>` (or the `DEOBFUSCATOR_JRE8` environment variable).

Build from source with the bundled Maven wrapper: `./mvnw package` (`mvnw.cmd` on Windows). The jar ends up in `target/`.

## Sandbox string decryption (any obfuscator, any Java version)

`general.SandboxStringTransformer` is the recommended way to recover encrypted strings from modern inputs.
Instead of emulating the decryption routines with the Java 8-only `javavm`, it **executes them in a separate,
isolated JVM process** (the same JDK that runs the deobfuscator, so Java 11-25 class files, records,
`invokedynamic` string concatenation, `MethodHandles`, ... all just work) and patches the results back as constants:

* strings / `String[]` pools decrypted in `<clinit>` and stored in static fields (Zelix, Stringer, ...);
* `INVOKESTATIC` decrypt calls with constant arguments: `(II)String`, `(String)String`, `(J)String`, ... (Zelix, Allatori, DashO, Paramorphism, custom);
* decryptors that inspect the call stack (Zelix "caller-sensitive" mode) are invoked through a trampoline that carries the original caller's name;
* decryptor methods left without callers are removed.

```yaml
input: input.jar
output: output.jar
transformers:
  - general.SandboxStringTransformer:
      timeoutMillis: 10000      # per call; the sandbox JVM is restarted on timeout/crash
      maxHeapMb: 512
      removeDecryptors: true
      ownerFilter: "com/example/.*"   # optional regex: only execute decryptors declared in matching classes
      # java: C:/jdks/jdk-22/bin/java  # optional: run the sandbox on another JDK
```

**The obfuscated code really runs.** The sandbox is a child process with a throw-away home/temp directory, a heap cap,
a per-call timeout and (on JDK 11-23) a `SecurityManager` that blocks network, file writes, process execution and
`System.exit`. On JDK 24+ the security manager no longer exists and only the process isolation remains. Only use it on
inputs you are entitled to analyse, and preferably not on a machine holding anything sensitive.

## Quick Start

* [Download](https://github.com/java-deobfuscator/deobfuscator/releases) the deobfuscator. The latest build is recommended.
* If you know what obfuscators were used, skip the next two steps
* Create `detect.yml` with the following contents. Replace `input.jar` with the name of the input
```yaml
input: input.jar
detect: true
```
* Run `java -jar deobfuscator.jar --config detect.yml` to determine the obfuscators used
* Create `config.yml` with the following contents. Replace `input.jar` with the name of the input
```yaml
input: input.jar
output: output.jar
transformers:
  - [fully-qualified-name-of-transformer]
  - [fully-qualified-name-of-transformer]
  - [fully-qualified-name-of-transformer]
  - ... etc
``` 
* Run `java -jar deobfuscator.jar`
* Re-run the detection if the JAR was not fully deobfuscated - it's possible to layer obfuscations

Take a look at [USAGE.md](USAGE.md) or [wiki](https://github.com/java-deobfuscator/deobfuscator/wiki) for more information.

## It didn't work

If you're trying to recover the names of classes or methods, tough luck. That information is typically stripped out and there's no way to recover it.

If you are using one of our transformers, check out the [commonerrors](commonerrors) folder to check for tips.

Otherwise, check out [this guide](CUSTOMTRANSFORMER.md) on how to implement your own transformer (also, open a issue/PR so I can add support for it)

## Supported Obfuscators

* [Zelix Klassmaster](http://www.zelix.com/)  
* [Stringer](https://jfxstore.com/stringer/)  
* [Allatori](http://www.allatori.com/)  
* [DashO](https://www.preemptive.com/products/dasho/overview)  
* [DexGuard](https://www.guardsquare.com/dexguard)    
* [ClassGuard](https://www.zenofx.com/classguard/)  
* Smoke (dead, website archive [here](https://web.archive.org/web/20170918112921/https://newtownia.net/smoke/))   
* SkidSuite2 (dead, archive [here](https://github.com/GenericException/SkidSuite/tree/master/archive/skidsuite-2))

## List of Transformers

The automagic detection should be able to recommend the transformers you'll need to use. However, it may not be up to date. If you're familiar with Java reverse engineering, feel free to [take a look around](src/main/java/com/javadeobfuscator/deobfuscator/transformers) and use what you need. 

## FAQs

#### I got an error that says "Could not locate a class file"
You need to specify all the JARs that the input file references on `path`. The Java runtime itself is loaded
automatically from the running JVM (only the `java.*` modules; add `runtimeModules: ["java.*", "jdk.*"]` to
the config to load everything, or `loadRuntime: false` to disable it and supply `rt.jar`/a JDK home yourself).

#### I got an error that says "The embedded javavm requires a Java 8 runtime"
The transformer you selected emulates the obfuscated code inside `javavm`, which only understands the Java 8
class library. Install any JDK 8 / JRE 8 and run
`java -Ddeobfuscator.jre8="C:\Program Files\Java\jre1.8.0_xxx" -jar deobfuscator.jar ...`

#### I got an `OutOfMemoryError: Java heap space`
Every class of the input is kept in memory. Large inputs (tens of thousands of classes) need a bigger heap, e.g.
`java -Xmx6g -jar deobfuscator.jar`.

#### I got an error that says "A StackOverflowError occurred during deobfuscation"
Increase your stack size. For example, `java -Xss128m -jar deobfuscator.jar`

#### Does this work on Android apps?
Technically, yes, you could use something like [dex2jar](https://github.com/pxb1988/dex2jar)
or [enjarify](https://github.com/storyyeller/enjarify). However, dex -> jar conversion is lossy at best.
Try [simplify](https://github.com/CalebFenton/simplify) or [dex-oracle](https://github.com/CalebFenton/dex-oracle) first.
They were written specifically for Android apps.

## Licensing

Java Deobfuscator is licensed under the Apache 2.0 license.
