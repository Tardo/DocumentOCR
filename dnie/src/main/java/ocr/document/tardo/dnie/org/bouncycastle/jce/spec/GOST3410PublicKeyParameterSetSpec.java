package org.bouncycastle.jce.spec;

import java.math.BigInteger;

public class GOST3410PublicKeyParameterSetSpec {
    /* renamed from: a */
    private BigInteger f105a;
    /* renamed from: p */
    private BigInteger f106p;
    /* renamed from: q */
    private BigInteger f107q;

    public GOST3410PublicKeyParameterSetSpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f106p = bigInteger;
        this.f107q = bigInteger2;
        this.f105a = bigInteger3;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof GOST3410PublicKeyParameterSetSpec)) {
            return false;
        }
        GOST3410PublicKeyParameterSetSpec gOST3410PublicKeyParameterSetSpec = (GOST3410PublicKeyParameterSetSpec) obj;
        return this.f105a.equals(gOST3410PublicKeyParameterSetSpec.f105a) && this.f106p.equals(gOST3410PublicKeyParameterSetSpec.f106p) && this.f107q.equals(gOST3410PublicKeyParameterSetSpec.f107q);
    }

    public BigInteger getA() {
        return this.f105a;
    }

    public BigInteger getP() {
        return this.f106p;
    }

    public BigInteger getQ() {
        return this.f107q;
    }

    public int hashCode() {
        return (this.f105a.hashCode() ^ this.f106p.hashCode()) ^ this.f107q.hashCode();
    }
}
