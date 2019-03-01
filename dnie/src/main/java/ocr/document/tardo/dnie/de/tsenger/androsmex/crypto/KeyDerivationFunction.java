package de.tsenger.androsmex.crypto;

import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA256Digest;

public class KeyDerivationFunction {
    private static final byte[] PARITY = new byte[]{(byte) 8, (byte) 1, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 2, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 3, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 4, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 5, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 6, (byte) 8};
    private byte[] mergedData = null;

    public static byte[] getMRZBytes(String documentNr, String dateOfBirth, String dateOfExpiry) {
        byte[] passwordBytes = (documentNr + dateOfBirth + dateOfExpiry).getBytes();
        byte[] K = new byte[20];
        SHA1Digest sha1 = new SHA1Digest();
        sha1.update(passwordBytes, 0, passwordBytes.length);
        sha1.doFinal(K, 0);
        return K;
    }

    public KeyDerivationFunction(byte[] K, int c) {
        if (c <= 0 || c > 3) {
            throw new IllegalArgumentException("c must be 1, 2 or 3!");
        }
        byte[] cBytes = intToByteArray(c);
        this.mergedData = new byte[(K.length + cBytes.length)];
        System.arraycopy(K, 0, this.mergedData, 0, K.length);
        System.arraycopy(cBytes, 0, this.mergedData, K.length, cBytes.length);
    }

    public KeyDerivationFunction(byte[] K, byte[] r, int c) throws IllegalArgumentException {
        if (c <= 0 || c > 3) {
            throw new IllegalArgumentException("c must be 1, 2 or 3!");
        }
        byte[] cBytes = intToByteArray(c);
        this.mergedData = new byte[((K.length + r.length) + cBytes.length)];
        System.arraycopy(K, 0, this.mergedData, 0, K.length);
        System.arraycopy(r, 0, this.mergedData, K.length, r.length);
        System.arraycopy(cBytes, 0, this.mergedData, K.length + r.length, cBytes.length);
    }

    public byte[] getDESedeKey() {
        byte[] checksum = new byte[20];
        SHA1Digest sha1 = new SHA1Digest();
        sha1.update(this.mergedData, 0, this.mergedData.length);
        sha1.doFinal(checksum, 0);
        byte[] ka = new byte[8];
        byte[] kb = new byte[8];
        System.arraycopy(checksum, 0, ka, 0, ka.length);
        System.arraycopy(checksum, 8, kb, 0, kb.length);
        adjustParity(ka, 0);
        adjustParity(kb, 0);
        byte[] key = new byte[24];
        System.arraycopy(ka, 0, key, 0, 8);
        System.arraycopy(kb, 0, key, 8, 8);
        System.arraycopy(ka, 0, key, 16, 8);
        return key;
    }

    public byte[] getAES128Key() {
        byte[] checksum = new byte[20];
        SHA1Digest sha1 = new SHA1Digest();
        sha1.update(this.mergedData, 0, this.mergedData.length);
        sha1.doFinal(checksum, 0);
        byte[] keydata = new byte[16];
        System.arraycopy(checksum, 0, keydata, 0, 16);
        return keydata;
    }

    public byte[] getAES192Key() {
        byte[] keydata = new byte[24];
        System.arraycopy(getAES256Key(), 0, keydata, 0, 24);
        return keydata;
    }

    public byte[] getAES256Key() {
        byte[] checksum = new byte[32];
        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(this.mergedData, 0, this.mergedData.length);
        sha256.doFinal(checksum, 0);
        return checksum;
    }

    private void adjustParity(byte[] key, int offset) {
        for (int i = offset; i < 8; i++) {
            key[i] = (byte) ((PARITY[key[i] & 255] == (byte) 8 ? 1 : 0) ^ key[i]);
        }
    }

    private byte[] intToByteArray(int c) {
        byte[] intBytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            int shift = i << 3;
            intBytes[3 - i] = (byte) (((255 << shift) & c) >>> shift);
        }
        return intBytes;
    }
}
