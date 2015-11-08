package my;

public final class SHA512 {
    public static native byte[] sha512(byte[] message);
    static {
        System.loadLibrary("JNISHA512");
    }
}
