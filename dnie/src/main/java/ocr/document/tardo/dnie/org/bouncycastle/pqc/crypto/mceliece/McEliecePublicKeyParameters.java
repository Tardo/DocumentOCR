package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

public class McEliecePublicKeyParameters extends McElieceKeyParameters {
    /* renamed from: g */
    private GF2Matrix f656g;
    /* renamed from: n */
    private int f657n;
    private String oid;
    /* renamed from: t */
    private int f658t;

    public McEliecePublicKeyParameters(String str, int i, int i2, GF2Matrix gF2Matrix, McElieceParameters mcElieceParameters) {
        super(false, mcElieceParameters);
        this.oid = str;
        this.f657n = i;
        this.f658t = i2;
        this.f656g = new GF2Matrix(gF2Matrix);
    }

    public McEliecePublicKeyParameters(String str, int i, int i2, byte[] bArr, McElieceParameters mcElieceParameters) {
        super(false, mcElieceParameters);
        this.oid = str;
        this.f657n = i2;
        this.f658t = i;
        this.f656g = new GF2Matrix(bArr);
    }

    public GF2Matrix getG() {
        return this.f656g;
    }

    public int getK() {
        return this.f656g.getNumRows();
    }

    public int getN() {
        return this.f657n;
    }

    public String getOIDString() {
        return this.oid;
    }

    public int getT() {
        return this.f658t;
    }
}
