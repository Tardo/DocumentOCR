package org.spongycastle.jce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.spongycastle.crypto.engines.GOST28147Engine;

public class GOST28147ParameterSpec implements AlgorithmParameterSpec {
    private byte[] iv;
    private byte[] sBox;

    public GOST28147ParameterSpec(byte[] sBox) {
        this.iv = null;
        this.sBox = null;
        this.sBox = new byte[sBox.length];
        System.arraycopy(sBox, 0, this.sBox, 0, sBox.length);
    }

    public GOST28147ParameterSpec(byte[] sBox, byte[] iv) {
        this(sBox);
        this.iv = new byte[iv.length];
        System.arraycopy(iv, 0, this.iv, 0, iv.length);
    }

    public GOST28147ParameterSpec(String sBoxName) {
        this.iv = null;
        this.sBox = null;
        this.sBox = GOST28147Engine.getSBox(sBoxName);
    }

    public GOST28147ParameterSpec(String sBoxName, byte[] iv) {
        this(sBoxName);
        this.iv = new byte[iv.length];
        System.arraycopy(iv, 0, this.iv, 0, iv.length);
    }

    public byte[] getSbox() {
        return this.sBox;
    }

    public byte[] getIV() {
        if (this.iv == null) {
            return null;
        }
        byte[] tmp = new byte[this.iv.length];
        System.arraycopy(this.iv, 0, tmp, 0, tmp.length);
        return tmp;
    }
}
