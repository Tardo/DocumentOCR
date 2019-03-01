package org.bouncycastle.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class IESParameterSpec implements AlgorithmParameterSpec {
    private int cipherKeySize;
    private byte[] derivation;
    private byte[] encoding;
    private int macKeySize;

    public IESParameterSpec(byte[] bArr, byte[] bArr2, int i) {
        this(bArr, bArr2, i, -1);
    }

    public IESParameterSpec(byte[] bArr, byte[] bArr2, int i, int i2) {
        if (bArr != null) {
            this.derivation = new byte[bArr.length];
            System.arraycopy(bArr, 0, this.derivation, 0, bArr.length);
        } else {
            this.derivation = null;
        }
        if (bArr2 != null) {
            this.encoding = new byte[bArr2.length];
            System.arraycopy(bArr2, 0, this.encoding, 0, bArr2.length);
        } else {
            this.encoding = null;
        }
        this.macKeySize = i;
        this.cipherKeySize = i2;
    }

    public int getCipherKeySize() {
        return this.cipherKeySize;
    }

    public byte[] getDerivationV() {
        return this.derivation;
    }

    public byte[] getEncodingV() {
        return this.encoding;
    }

    public int getMacKeySize() {
        return this.macKeySize;
    }
}
