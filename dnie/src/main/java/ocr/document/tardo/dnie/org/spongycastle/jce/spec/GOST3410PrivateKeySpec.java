package org.spongycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class GOST3410PrivateKeySpec implements KeySpec {
    /* renamed from: a */
    private BigInteger f186a;
    /* renamed from: p */
    private BigInteger f187p;
    /* renamed from: q */
    private BigInteger f188q;
    /* renamed from: x */
    private BigInteger f189x;

    public GOST3410PrivateKeySpec(BigInteger x, BigInteger p, BigInteger q, BigInteger a) {
        this.f189x = x;
        this.f187p = p;
        this.f188q = q;
        this.f186a = a;
    }

    public BigInteger getX() {
        return this.f189x;
    }

    public BigInteger getP() {
        return this.f187p;
    }

    public BigInteger getQ() {
        return this.f188q;
    }

    public BigInteger getA() {
        return this.f186a;
    }
}
