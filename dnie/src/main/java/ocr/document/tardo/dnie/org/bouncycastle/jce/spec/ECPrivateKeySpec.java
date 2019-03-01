package org.bouncycastle.jce.spec;

import java.math.BigInteger;

public class ECPrivateKeySpec extends ECKeySpec {
    /* renamed from: d */
    private BigInteger f301d;

    public ECPrivateKeySpec(BigInteger bigInteger, ECParameterSpec eCParameterSpec) {
        super(eCParameterSpec);
        this.f301d = bigInteger;
    }

    public BigInteger getD() {
        return this.f301d;
    }
}
