package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class RSAPrivateCrtKeyParameters extends RSAKeyParameters {
    private BigInteger dP;
    private BigInteger dQ;
    /* renamed from: e */
    private BigInteger f643e;
    /* renamed from: p */
    private BigInteger f644p;
    /* renamed from: q */
    private BigInteger f645q;
    private BigInteger qInv;

    public RSAPrivateCrtKeyParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, BigInteger bigInteger5, BigInteger bigInteger6, BigInteger bigInteger7, BigInteger bigInteger8) {
        super(true, bigInteger, bigInteger3);
        this.f643e = bigInteger2;
        this.f644p = bigInteger4;
        this.f645q = bigInteger5;
        this.dP = bigInteger6;
        this.dQ = bigInteger7;
        this.qInv = bigInteger8;
    }

    public BigInteger getDP() {
        return this.dP;
    }

    public BigInteger getDQ() {
        return this.dQ;
    }

    public BigInteger getP() {
        return this.f644p;
    }

    public BigInteger getPublicExponent() {
        return this.f643e;
    }

    public BigInteger getQ() {
        return this.f645q;
    }

    public BigInteger getQInv() {
        return this.qInv;
    }
}
