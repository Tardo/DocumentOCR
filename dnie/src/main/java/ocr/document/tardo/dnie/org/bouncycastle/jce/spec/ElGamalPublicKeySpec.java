package org.bouncycastle.jce.spec;

import java.math.BigInteger;

public class ElGamalPublicKeySpec extends ElGamalKeySpec {
    /* renamed from: y */
    private BigInteger f304y;

    public ElGamalPublicKeySpec(BigInteger bigInteger, ElGamalParameterSpec elGamalParameterSpec) {
        super(elGamalParameterSpec);
        this.f304y = bigInteger;
    }

    public BigInteger getY() {
        return this.f304y;
    }
}
