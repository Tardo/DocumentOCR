package org.spongycastle.jce.spec;

import java.math.BigInteger;

public class ElGamalPrivateKeySpec extends ElGamalKeySpec {
    /* renamed from: x */
    private BigInteger f427x;

    public ElGamalPrivateKeySpec(BigInteger x, ElGamalParameterSpec spec) {
        super(spec);
        this.f427x = x;
    }

    public BigInteger getX() {
        return this.f427x;
    }
}
