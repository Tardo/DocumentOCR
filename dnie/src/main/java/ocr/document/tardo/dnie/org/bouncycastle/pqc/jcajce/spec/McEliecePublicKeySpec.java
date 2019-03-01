package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

public class McEliecePublicKeySpec implements KeySpec {
    /* renamed from: g */
    private GF2Matrix f143g;
    /* renamed from: n */
    private int f144n;
    private String oid;
    /* renamed from: t */
    private int f145t;

    public McEliecePublicKeySpec(String str, int i, int i2, GF2Matrix gF2Matrix) {
        this.oid = str;
        this.f144n = i;
        this.f145t = i2;
        this.f143g = new GF2Matrix(gF2Matrix);
    }

    public McEliecePublicKeySpec(String str, int i, int i2, byte[] bArr) {
        this.oid = str;
        this.f144n = i2;
        this.f145t = i;
        this.f143g = new GF2Matrix(bArr);
    }

    public GF2Matrix getG() {
        return this.f143g;
    }

    public int getN() {
        return this.f144n;
    }

    public String getOIDString() {
        return this.oid;
    }

    public int getT() {
        return this.f145t;
    }
}
