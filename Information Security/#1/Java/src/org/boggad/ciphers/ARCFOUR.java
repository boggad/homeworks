package org.boggad.ciphers;

import my.SHA512;

public final class ARCFOUR {

    private byte[] sBox;
    private final int keyLength;
    private final byte[] key;

    private int PRGCounter1, PRGCounter2;


    private ARCFOUR(byte[] key) {
        this.key = key.clone();
        this.keyLength = this.key.length;

        init(this.key);
    }

    public static ARCFOUR getInstance(byte[] key) {
        return new ARCFOUR(key);
    }

    private void init(byte[] key) {
        sBox = null;
        sBox = new byte[256];
        for (int i = 0; i < 256; i++) {
            sBox[i] = (byte) i;
        }
        for (int i = 0, j = 0; i < 256; i++) {
            j = (j + (sBox[i] & 0xff) + (key[i % keyLength] & 0xff)) % 256;
            sBox[i] ^= sBox[j];
            sBox[j] = (byte) (sBox[i] ^ sBox[j]);
            sBox[i] ^= sBox[j];
        }

        PRGCounter1 = 0;
        PRGCounter2 = 0;
    }

    public void reinitialize() {
        init(key);
    }

    public byte nextRandomByte() {

        PRGCounter1 = (PRGCounter1 + 1) % 256;
        PRGCounter2 = (PRGCounter2 + (sBox[PRGCounter1] & 0xff)) % 256;
        sBox[PRGCounter1] ^= sBox[PRGCounter2];
        sBox[PRGCounter2] = (byte) (sBox[PRGCounter1] ^ sBox[PRGCounter2]);
        sBox[PRGCounter1] ^= sBox[PRGCounter2];
        int tmp = ((sBox[PRGCounter1] & 0xff) + (sBox[PRGCounter2] & 0xff)) % 256;
        return sBox[tmp];
    }

    public byte[] rc4(byte[] in, int sha512Rounds, boolean passFirstMb) {
        byte[] keyForUse = key;
        if (sha512Rounds > 0) {
            keyForUse = SHA512.sha512(key);
            for (int i = 0; i < sha512Rounds; i++) {
                keyForUse = SHA512.sha512(keyForUse);
            }
        }
        if (keyForUse == null) {
            throw new NullPointerException();
        }

        init(keyForUse);

        if (passFirstMb) {
            for (int i = 0; i < 1024; i++) {
                byte mock = nextRandomByte();
            }
        }

        byte[] out = new byte[in.length];

        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) ((nextRandomByte() ^ in[i]) & 0xff);
        }

        return out;
    }

}
