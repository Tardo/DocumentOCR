package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class DSAPublicKeyParameters extends DSAKeyParameters {
    /* renamed from: y */
    private BigInteger f636y;

    public DSAPublicKeyParameters(BigInteger bigInteger, DSAParameters dSAParameters) {
        super(false, dSAParameters);
        this.f636y = bigInteger;
    }

    public BigInteger getY() {
        return this.f636y;
    }
}
