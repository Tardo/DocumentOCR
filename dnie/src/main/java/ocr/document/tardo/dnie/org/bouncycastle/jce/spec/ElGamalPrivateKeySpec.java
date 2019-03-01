package org.bouncycastle.jce.spec;

import java.math.BigInteger;

public class ElGamalPrivateKeySpec extends ElGamalKeySpec {
    /* renamed from: x */
    private BigInteger f303x;

    public ElGamalPrivateKeySpec(BigInteger bigInteger, ElGamalParameterSpec elGamalParameterSpec) {
        super(elGamalParameterSpec);
        this.f303x = bigInteger;
    }

    public BigInteger getX() {
        return this.f303x;
    }
}
