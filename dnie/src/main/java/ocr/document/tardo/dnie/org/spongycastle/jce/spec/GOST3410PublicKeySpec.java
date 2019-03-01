package org.spongycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class GOST3410PublicKeySpec implements KeySpec {
    /* renamed from: a */
    private BigInteger f193a;
    /* renamed from: p */
    private BigInteger f194p;
    /* renamed from: q */
    private BigInteger f195q;
    /* renamed from: y */
    private BigInteger f196y;

    public GOST3410PublicKeySpec(BigInteger y, BigInteger p, BigInteger q, BigInteger a) {
        this.f196y = y;
        this.f194p = p;
        this.f195q = q;
        this.f193a = a;
    }

    public BigInteger getY() {
        return this.f196y;
    }

    public BigInteger getP() {
        return this.f194p;
    }

    public BigInteger getQ() {
        return this.f195q;
    }

    public BigInteger getA() {
        return this.f193a;
    }
}
