package com.javadeobfuscator.deobfuscator.sandbox;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Wire format shared by {@link SandboxExecutor} (parent) and {@link SandboxAgent} (child process).
 * One JSON object per line on stdin/stdout of the child. Values are tagged with a JVM descriptor-like
 * type so that both ends can marshal them without reflection.
 */
public final class SandboxProtocol {
    private SandboxProtocol() {
    }

    public static final String OP_PING = "ping";
    public static final String OP_INIT_CLASS = "initClass";
    public static final String OP_INVOKE_STATIC = "invokeStatic";
    public static final String OP_GET_STATIC = "getStatic";
    public static final String OP_DEFINE_CLASS = "defineClass";
    public static final String OP_SHUTDOWN = "shutdown";

    public static final class Request {
        public long id;
        public String op;
        public String owner;
        public String name;
        public String desc;
        public List<Value> args;
        /** base64 class bytes for {@link #OP_DEFINE_CLASS} */
        public String bytes;
    }

    public static final class Response {
        public long id;
        public boolean ok;
        public Value value;
        public String error;
        public String errorType;
    }

    /**
     * A marshalled value. {@code t} is one of: {@code Z B C S I J F D} (boxed primitives, {@code v} textual),
     * {@code String} ({@code v} textual, {@code isNull} for null), {@code String[]} ({@code list}),
     * {@code byte[]} / {@code char[]} / {@code int[]} / {@code long[]} ({@code v} base64-encoded, big-endian),
     * {@code null} or {@code Object} (unsupported reference; {@code v} holds {@code toString()}).
     */
    public static final class Value {
        public String t;
        public String v;
        public List<Value> list;
        public boolean isNull;

        public static Value of(Object o) {
            Value val = new Value();
            if (o == null) {
                val.t = "null";
                val.isNull = true;
            } else if (o instanceof String) {
                val.t = "String";
                val.v = (String) o;
            } else if (o instanceof Integer) {
                val.t = "I";
                val.v = o.toString();
            } else if (o instanceof Long) {
                val.t = "J";
                val.v = o.toString();
            } else if (o instanceof Boolean) {
                val.t = "Z";
                val.v = o.toString();
            } else if (o instanceof Character) {
                val.t = "C";
                val.v = Integer.toString((Character) o);
            } else if (o instanceof Byte) {
                val.t = "B";
                val.v = o.toString();
            } else if (o instanceof Short) {
                val.t = "S";
                val.v = o.toString();
            } else if (o instanceof Float) {
                val.t = "F";
                val.v = Integer.toString(Float.floatToRawIntBits((Float) o));
            } else if (o instanceof Double) {
                val.t = "D";
                val.v = Long.toString(Double.doubleToRawLongBits((Double) o));
            } else if (o instanceof String[]) {
                val.t = "String[]";
                val.list = new ArrayList<>();
                for (String s : (String[]) o) {
                    val.list.add(of(s));
                }
            } else if (o instanceof byte[]) {
                val.t = "byte[]";
                val.v = Base64.getEncoder().encodeToString((byte[]) o);
            } else if (o instanceof char[]) {
                char[] arr = (char[]) o;
                byte[] b = new byte[arr.length * 2];
                for (int i = 0; i < arr.length; i++) {
                    b[i * 2] = (byte) (arr[i] >> 8);
                    b[i * 2 + 1] = (byte) arr[i];
                }
                val.t = "char[]";
                val.v = Base64.getEncoder().encodeToString(b);
            } else if (o instanceof int[]) {
                int[] arr = (int[]) o;
                byte[] b = new byte[arr.length * 4];
                for (int i = 0; i < arr.length; i++) {
                    b[i * 4] = (byte) (arr[i] >> 24);
                    b[i * 4 + 1] = (byte) (arr[i] >> 16);
                    b[i * 4 + 2] = (byte) (arr[i] >> 8);
                    b[i * 4 + 3] = (byte) arr[i];
                }
                val.t = "int[]";
                val.v = Base64.getEncoder().encodeToString(b);
            } else if (o instanceof long[]) {
                long[] arr = (long[]) o;
                byte[] b = new byte[arr.length * 8];
                for (int i = 0; i < arr.length; i++) {
                    for (int j = 0; j < 8; j++) {
                        b[i * 8 + j] = (byte) (arr[i] >> (56 - 8 * j));
                    }
                }
                val.t = "long[]";
                val.v = Base64.getEncoder().encodeToString(b);
            } else {
                val.t = "Object";
                val.v = o.getClass().getName() + "@" + o;
            }
            return val;
        }

        public Object toObject() {
            if (isNull || "null".equals(t)) {
                return null;
            }
            switch (t) {
                case "String":
                    return v;
                case "I":
                    return Integer.parseInt(v);
                case "J":
                    return Long.parseLong(v);
                case "Z":
                    return Boolean.parseBoolean(v);
                case "C":
                    return (char) Integer.parseInt(v);
                case "B":
                    return Byte.parseByte(v);
                case "S":
                    return Short.parseShort(v);
                case "F":
                    return Float.intBitsToFloat(Integer.parseInt(v));
                case "D":
                    return Double.longBitsToDouble(Long.parseLong(v));
                case "String[]": {
                    String[] arr = new String[list.size()];
                    for (int i = 0; i < arr.length; i++) {
                        arr[i] = (String) list.get(i).toObject();
                    }
                    return arr;
                }
                case "byte[]":
                    return Base64.getDecoder().decode(v);
                case "char[]": {
                    byte[] b = Base64.getDecoder().decode(v);
                    char[] arr = new char[b.length / 2];
                    for (int i = 0; i < arr.length; i++) {
                        arr[i] = (char) (((b[i * 2] & 0xFF) << 8) | (b[i * 2 + 1] & 0xFF));
                    }
                    return arr;
                }
                case "int[]": {
                    byte[] b = Base64.getDecoder().decode(v);
                    int[] arr = new int[b.length / 4];
                    for (int i = 0; i < arr.length; i++) {
                        arr[i] = ((b[i * 4] & 0xFF) << 24) | ((b[i * 4 + 1] & 0xFF) << 16) | ((b[i * 4 + 2] & 0xFF) << 8) | (b[i * 4 + 3] & 0xFF);
                    }
                    return arr;
                }
                case "long[]": {
                    byte[] b = Base64.getDecoder().decode(v);
                    long[] arr = new long[b.length / 8];
                    for (int i = 0; i < arr.length; i++) {
                        long x = 0;
                        for (int j = 0; j < 8; j++) {
                            x = (x << 8) | (b[i * 8 + j] & 0xFF);
                        }
                        arr[i] = x;
                    }
                    return arr;
                }
                default:
                    return new Unsupported(v);
            }
        }
    }

    /** Marker for a reference value that could not be marshalled across the process boundary. */
    public static final class Unsupported {
        public final String description;

        public Unsupported(String description) {
            this.description = description;
        }

        @Override
        public String toString() {
            return description;
        }
    }
}
