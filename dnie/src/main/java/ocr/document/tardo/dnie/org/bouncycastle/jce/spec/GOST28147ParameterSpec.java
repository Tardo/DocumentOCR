package org.bouncycastle.jce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.crypto.engines.GOST28147Engine;

public class GOST28147ParameterSpec implements AlgorithmParameterSpec {
    private byte[] iv;
    private byte[] sBox;

    public GOST28147ParameterSpec(String str) {
        this.iv = null;
        this.sBox = null;
        this.sBox = GOST28147Engine.getSBox(str);
    }

    public GOST28147ParameterSpec(String str, byte[] bArr) {
        this(str);
        this.iv = new byte[bArr.length];
        System.arraycopy(bArr, 0, this.iv, 0, bArr.length);
    }

    public GOST28147ParameterSpec(byte[] bArr) {
        this.iv = null;
        this.sBox = null;
        this.sBox = new byte[bArr.length];
        System.arraycopy(bArr, 0, this.sBox, 0, bArr.length);
    }

    public GOST28147ParameterSpec(byte[] bArr, byte[] bArr2) {
        this(bArr);
        this.iv = new byte[bArr2.length];
        System.arraycopy(bArr2, 0, this.iv, 0, bArr2.length);
    }

    public byte[] getIV() {
        if (this.iv == null) {
            return null;
        }
        Object obj = new byte[this.iv.length];
        System.arraycopy(this.iv, 0, obj, 0, obj.length);
        return obj;
    }

    public byte[] getSbox() {
        return this.sBox;
    }
}
