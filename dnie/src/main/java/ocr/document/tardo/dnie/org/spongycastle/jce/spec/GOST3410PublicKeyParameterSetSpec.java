package org.spongycastle.jce.spec;

import java.math.BigInteger;

public class GOST3410PublicKeyParameterSetSpec {
    /* renamed from: a */
    private BigInteger f190a;
    /* renamed from: p */
    private BigInteger f191p;
    /* renamed from: q */
    private BigInteger f192q;

    public GOST3410PublicKeyParameterSetSpec(BigInteger p, BigInteger q, BigInteger a) {
        this.f191p = p;
        this.f192q = q;
        this.f190a = a;
    }

    public BigInteger getP() {
        return this.f191p;
    }

    public BigInteger getQ() {
        return this.f192q;
    }

    public BigInteger getA() {
        return this.f190a;
    }

    public boolean equals(Object o) {
        if (!(o instanceof GOST3410PublicKeyParameterSetSpec)) {
            return false;
        }
        GOST3410PublicKeyParameterSetSpec other = (GOST3410PublicKeyParameterSetSpec) o;
        if (this.f190a.equals(other.f190a) && this.f191p.equals(other.f191p) && this.f192q.equals(other.f192q)) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return (this.f190a.hashCode() ^ this.f191p.hashCode()) ^ this.f192q.hashCode();
    }
}
