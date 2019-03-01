package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class RC2Parameters implements CipherParameters {
    private int bits;
    private byte[] key;

    public RC2Parameters(byte[] bArr) {
        this(bArr, bArr.length > 128 ? 1024 : bArr.length * 8);
    }

    public RC2Parameters(byte[] bArr, int i) {
        this.key = new byte[bArr.length];
        this.bits = i;
        System.arraycopy(bArr, 0, this.key, 0, bArr.length);
    }

    public int getEffectiveKeyBits() {
        return this.bits;
    }

    public byte[] getKey() {
        return this.key;
    }
}
