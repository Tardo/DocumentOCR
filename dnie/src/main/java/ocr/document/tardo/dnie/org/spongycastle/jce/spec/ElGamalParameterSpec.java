package org.spongycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public class ElGamalParameterSpec implements AlgorithmParameterSpec {
    /* renamed from: g */
    private BigInteger f184g;
    /* renamed from: p */
    private BigInteger f185p;

    public ElGamalParameterSpec(BigInteger p, BigInteger g) {
        this.f185p = p;
        this.f184g = g;
    }

    public BigInteger getP() {
        return this.f185p;
    }

    public BigInteger getG() {
        return this.f184g;
    }
}
