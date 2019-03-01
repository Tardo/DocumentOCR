package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class GOST3410PrivateKeySpec implements KeySpec {
    /* renamed from: a */
    private BigInteger f101a;
    /* renamed from: p */
    private BigInteger f102p;
    /* renamed from: q */
    private BigInteger f103q;
    /* renamed from: x */
    private BigInteger f104x;

    public GOST3410PrivateKeySpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        this.f104x = bigInteger;
        this.f102p = bigInteger2;
        this.f103q = bigInteger3;
        this.f101a = bigInteger4;
    }

    public BigInteger getA() {
        return this.f101a;
    }

    public BigInteger getP() {
        return this.f102p;
    }

    public BigInteger getQ() {
        return this.f103q;
    }

    public BigInteger getX() {
        return this.f104x;
    }
}
