package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

public class McElieceCCA2PublicKeySpec implements KeySpec {
    private GF2Matrix matrixG;
    /* renamed from: n */
    private int f138n;
    private String oid;
    /* renamed from: t */
    private int f139t;

    public McElieceCCA2PublicKeySpec(String str, int i, int i2, GF2Matrix gF2Matrix) {
        this.oid = str;
        this.f138n = i;
        this.f139t = i2;
        this.matrixG = new GF2Matrix(gF2Matrix);
    }

    public McElieceCCA2PublicKeySpec(String str, int i, int i2, byte[] bArr) {
        this.oid = str;
        this.f138n = i;
        this.f139t = i2;
        this.matrixG = new GF2Matrix(bArr);
    }

    public GF2Matrix getMatrixG() {
        return this.matrixG;
    }

    public int getN() {
        return this.f138n;
    }

    public String getOIDString() {
        return this.oid;
    }

    public int getT() {
        return this.f139t;
    }
}
