package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.ECPoint;

public class ECPublicKeyParameters extends ECKeyParameters {
    /* renamed from: Q */
    ECPoint f638Q;

    public ECPublicKeyParameters(ECPoint eCPoint, ECDomainParameters eCDomainParameters) {
        super(false, eCDomainParameters);
        this.f638Q = eCPoint;
    }

    public ECPoint getQ() {
        return this.f638Q;
    }
}
