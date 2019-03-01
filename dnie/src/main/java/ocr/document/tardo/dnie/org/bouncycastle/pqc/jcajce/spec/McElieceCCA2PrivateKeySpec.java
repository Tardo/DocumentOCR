package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

public class McElieceCCA2PrivateKeySpec implements KeySpec {
    private GF2mField field;
    private PolynomialGF2mSmallM goppaPoly;
    /* renamed from: h */
    private GF2Matrix f134h;
    /* renamed from: k */
    private int f135k;
    /* renamed from: n */
    private int f136n;
    private String oid;
    /* renamed from: p */
    private Permutation f137p;
    private PolynomialGF2mSmallM[] qInv;

    public McElieceCCA2PrivateKeySpec(String str, int i, int i2, GF2mField gF2mField, PolynomialGF2mSmallM polynomialGF2mSmallM, Permutation permutation, GF2Matrix gF2Matrix, PolynomialGF2mSmallM[] polynomialGF2mSmallMArr) {
        this.oid = str;
        this.f136n = i;
        this.f135k = i2;
        this.field = gF2mField;
        this.goppaPoly = polynomialGF2mSmallM;
        this.f137p = permutation;
        this.f134h = gF2Matrix;
        this.qInv = polynomialGF2mSmallMArr;
    }

    public McElieceCCA2PrivateKeySpec(String str, int i, int i2, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, byte[][] bArr5) {
        this.oid = str;
        this.f136n = i;
        this.f135k = i2;
        this.field = new GF2mField(bArr);
        this.goppaPoly = new PolynomialGF2mSmallM(this.field, bArr2);
        this.f137p = new Permutation(bArr3);
        this.f134h = new GF2Matrix(bArr4);
        this.qInv = new PolynomialGF2mSmallM[bArr5.length];
        for (int i3 = 0; i3 < bArr5.length; i3++) {
            this.qInv[i3] = new PolynomialGF2mSmallM(this.field, bArr5[i3]);
        }
    }

    public GF2mField getField() {
        return this.field;
    }

    public PolynomialGF2mSmallM getGoppaPoly() {
        return this.goppaPoly;
    }

    public GF2Matrix getH() {
        return this.f134h;
    }

    public int getK() {
        return this.f135k;
    }

    public int getN() {
        return this.f136n;
    }

    public String getOIDString() {
        return this.oid;
    }

    public Permutation getP() {
        return this.f137p;
    }

    public PolynomialGF2mSmallM[] getQInv() {
        return this.qInv;
    }
}
