package org.spongycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;

public class ECParameterSpec implements AlgorithmParameterSpec {
    /* renamed from: G */
    private ECPoint f181G;
    private ECCurve curve;
    /* renamed from: h */
    private BigInteger f182h;
    /* renamed from: n */
    private BigInteger f183n;
    private byte[] seed;

    public ECParameterSpec(ECCurve curve, ECPoint G, BigInteger n) {
        this.curve = curve;
        this.f181G = G;
        this.f183n = n;
        this.f182h = BigInteger.valueOf(1);
        this.seed = null;
    }

    public ECParameterSpec(ECCurve curve, ECPoint G, BigInteger n, BigInteger h) {
        this.curve = curve;
        this.f181G = G;
        this.f183n = n;
        this.f182h = h;
        this.seed = null;
    }

    public ECParameterSpec(ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed) {
        this.curve = curve;
        this.f181G = G;
        this.f183n = n;
        this.f182h = h;
        this.seed = seed;
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public ECPoint getG() {
        return this.f181G;
    }

    public BigInteger getN() {
        return this.f183n;
    }

    public BigInteger getH() {
        return this.f182h;
    }

    public byte[] getSeed() {
        return this.seed;
    }

    public boolean equals(Object o) {
        if (!(o instanceof ECParameterSpec)) {
            return false;
        }
        ECParameterSpec other = (ECParameterSpec) o;
        if (getCurve().equals(other.getCurve()) && getG().equals(other.getG())) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return getCurve().hashCode() ^ getG().hashCode();
    }
}
