package org.spongycastle.jce.spec;

import java.math.BigInteger;

public class ECPrivateKeySpec extends ECKeySpec {
    /* renamed from: d */
    private BigInteger f425d;

    public ECPrivateKeySpec(BigInteger d, ECParameterSpec spec) {
        super(spec);
        this.f425d = d;
    }

    public BigInteger getD() {
        return this.f425d;
    }
}
