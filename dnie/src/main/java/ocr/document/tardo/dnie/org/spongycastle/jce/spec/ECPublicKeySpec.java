package org.spongycastle.jce.spec;

import org.spongycastle.math.ec.ECPoint;

public class ECPublicKeySpec extends ECKeySpec {
    /* renamed from: q */
    private ECPoint f426q;

    public ECPublicKeySpec(ECPoint q, ECParameterSpec spec) {
        super(spec);
        this.f426q = q;
    }

    public ECPoint getQ() {
        return this.f426q;
    }
}
