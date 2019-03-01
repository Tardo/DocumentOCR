package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class ECPrivateKeyParameters extends ECKeyParameters {
    /* renamed from: d */
    BigInteger f637d;

    public ECPrivateKeyParameters(BigInteger bigInteger, ECDomainParameters eCDomainParameters) {
        super(true, eCDomainParameters);
        this.f637d = bigInteger;
    }

    public BigInteger getD() {
        return this.f637d;
    }
}
