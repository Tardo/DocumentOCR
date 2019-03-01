package org.bouncycastle.pqc.jcajce.spec;

import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2;

public class ECCKeyGenParameterSpec implements AlgorithmParameterSpec {
    public static final int DEFAULT_M = 11;
    public static final int DEFAULT_T = 50;
    private int fieldPoly;
    /* renamed from: m */
    private int f131m;
    /* renamed from: n */
    private int f132n;
    /* renamed from: t */
    private int f133t;

    public ECCKeyGenParameterSpec() {
        this(11, 50);
    }

    public ECCKeyGenParameterSpec(int i) throws InvalidParameterException {
        if (i < 1) {
            throw new InvalidParameterException("key size must be positive");
        }
        this.f131m = 0;
        this.f132n = 1;
        while (this.f132n < i) {
            this.f132n <<= 1;
            this.f131m++;
        }
        this.f133t = this.f132n >>> 1;
        this.f133t /= this.f131m;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(this.f131m);
    }

    public ECCKeyGenParameterSpec(int i, int i2) throws InvalidParameterException {
        if (i < 1) {
            throw new InvalidParameterException("m must be positive");
        } else if (i > 32) {
            throw new InvalidParameterException("m is too large");
        } else {
            this.f131m = i;
            this.f132n = 1 << i;
            if (i2 < 0) {
                throw new InvalidParameterException("t must be positive");
            } else if (i2 > this.f132n) {
                throw new InvalidParameterException("t must be less than n = 2^m");
            } else {
                this.f133t = i2;
                this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(i);
            }
        }
    }

    public ECCKeyGenParameterSpec(int i, int i2, int i3) throws InvalidParameterException {
        this.f131m = i;
        if (i < 1) {
            throw new InvalidParameterException("m must be positive");
        } else if (i > 32) {
            throw new InvalidParameterException(" m is too large");
        } else {
            this.f132n = 1 << i;
            this.f133t = i2;
            if (i2 < 0) {
                throw new InvalidParameterException("t must be positive");
            } else if (i2 > this.f132n) {
                throw new InvalidParameterException("t must be less than n = 2^m");
            } else if (PolynomialRingGF2.degree(i3) == i && PolynomialRingGF2.isIrreducible(i3)) {
                this.fieldPoly = i3;
            } else {
                throw new InvalidParameterException("polynomial is not a field polynomial for GF(2^m)");
            }
        }
    }

    public int getFieldPoly() {
        return this.fieldPoly;
    }

    public int getM() {
        return this.f131m;
    }

    public int getN() {
        return this.f132n;
    }

    public int getT() {
        return this.f133t;
    }
}
