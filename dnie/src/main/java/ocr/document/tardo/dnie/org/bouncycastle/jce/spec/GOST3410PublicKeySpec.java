package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class GOST3410PublicKeySpec implements KeySpec {
    /* renamed from: a */
    private BigInteger f108a;
    /* renamed from: p */
    private BigInteger f109p;
    /* renamed from: q */
    private BigInteger f110q;
    /* renamed from: y */
    private BigInteger f111y;

    public GOST3410PublicKeySpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        this.f111y = bigInteger;
        this.f109p = bigInteger2;
        this.f110q = bigInteger3;
        this.f108a = bigInteger4;
    }

    public BigInteger getA() {
        return this.f108a;
    }

    public BigInteger getP() {
        return this.f109p;
    }

    public BigInteger getQ() {
        return this.f110q;
    }

    public BigInteger getY() {
        return this.f111y;
    }
}
