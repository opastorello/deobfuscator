# Usage
### As a library

```java
public class SomeRandomDeobfuscator {
    public static void main(String[] args) throws Throwable {
        Configuration config = new Configuration();
        config.setInput(new File("input.jar"));
        config.setOutput(new File("output.jar"));
        // Optional: libraries referenced by the input. The Java runtime of the current JVM is loaded
        // automatically (jrt:/); a JDK home (8 or 9+), .jar, .jmod or a directory of them is also accepted.
        config.setPath(Arrays.asList(
                new File("libs"),
                new File("C:\\Program Files\\Java\\jdk-21")   // explicit runtime, overrides the automatic one
        ));
        config.setTransformers(Arrays.asList(
                TransformerConfig.configFor(PeepholeOptimizer.class)
        ));
        new Deobfuscator(config).start();
    }
}
```

### CLI

If you don't want to import the project, you can always use the command line interface.

| Argument | Description |
| --- | --- |
| --config | The configuration file |

You may specify multiple transformers, and they will be applied in the order given. Order does matter as sometimes one transformation depends on another not being present.

If you wish to use one of the default transformers, then you may remove the `com.javadeobfuscator.deobfuscator.transformers` prefix.

Here is a sample `config.yaml`:

```yaml
input: input.jar
output: output.jar
transformers:
  - normalizer.MethodNormalizer:
      mapping-file: normalizer.txt
  - stringer.StringEncryptionTransformer
  - normalizer.ClassNormalizer: {}
    normalizer.FieldNormalizer: {}
```
