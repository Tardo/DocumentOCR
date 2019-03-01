package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2;

public class McElieceParameters implements CipherParameters {
    public static final int DEFAULT_M = 11;
    public static final int DEFAULT_T = 50;
    private int fieldPoly;
    /* renamed from: m */
    private int f325m;
    /* renamed from: n */
    private int f326n;
    /* renamed from: t */
    private int f327t;

    public McElieceParameters() {
        this(11, 50);
    }

    public McElieceParameters(int i) throws IllegalArgumentException {
        if (i < 1) {
            throw new IllegalArgumentException("key size must be positive");
        }
        this.f325m = 0;
        this.f326n = 1;
        while (this.f326n < i) {
            this.f326n <<= 1;
            this.f325m++;
        }
        this.f327t = this.f326n >>> 1;
        this.f327t /= this.f325m;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(this.f325m);
    }

    public McElieceParameters(int i, int i2) throws IllegalArgumentException {
        if (i < 1) {
            throw new IllegalArgumentException("m must be positive");
        } else if (i > 32) {
            throw new IllegalArgumentException("m is too large");
        } else {
            this.f325m = i;
            this.f326n = 1 << i;
            if (i2 < 0) {
                throw new IllegalArgumentException("t must be positive");
            } else if (i2 > this.f326n) {
                throw new IllegalArgumentException("t must be less than n = 2^m");
            } else {
                this.f327t = i2;
                this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(i);
            }
        }
    }

    public McElieceParameters(int i, int i2, int i3) throws IllegalArgumentException {
        this.f325m = i;
        if (i < 1) {
            throw new IllegalArgumentException("m must be positive");
        } else if (i > 32) {
            throw new IllegalArgumentException(" m is too large");
        } else {
            this.f326n = 1 << i;
            this.f327t = i2;
            if (i2 < 0) {
                throw new IllegalArgumentException("t must be positive");
            } else if (i2 > this.f326n) {
                throw new IllegalArgumentException("t must be less than n = 2^m");
            } else if (PolynomialRingGF2.degree(i3) == i && PolynomialRingGF2.isIrreducible(i3)) {
                this.fieldPoly = i3;
            } else {
                throw new IllegalArgumentException("polynomial is not a field polynomial for GF(2^m)");
            }
        }
    }

    public int getFieldPoly() {
        return this.fieldPoly;
    }

    public int getM() {
        return this.f325m;
    }

    public int getN() {
        return this.f326n;
    }

    public int getT() {
        return this.f327t;
    }
}
