package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public class ElGamalParameterSpec implements AlgorithmParameterSpec {
    /* renamed from: g */
    private BigInteger f99g;
    /* renamed from: p */
    private BigInteger f100p;

    public ElGamalParameterSpec(BigInteger bigInteger, BigInteger bigInteger2) {
        this.f100p = bigInteger;
        this.f99g = bigInteger2;
    }

    public BigInteger getG() {
        return this.f99g;
    }

    public BigInteger getP() {
        return this.f100p;
    }
}
