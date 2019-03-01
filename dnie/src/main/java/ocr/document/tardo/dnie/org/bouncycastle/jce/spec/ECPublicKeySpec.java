package org.bouncycastle.jce.spec;

import org.bouncycastle.math.ec.ECPoint;

public class ECPublicKeySpec extends ECKeySpec {
    /* renamed from: q */
    private ECPoint f302q;

    public ECPublicKeySpec(ECPoint eCPoint, ECParameterSpec eCParameterSpec) {
        super(eCParameterSpec);
        this.f302q = eCPoint;
    }

    public ECPoint getQ() {
        return this.f302q;
    }
}
