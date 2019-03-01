package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class DHPublicKeyParameters extends DHKeyParameters {
    /* renamed from: y */
    private BigInteger f634y;

    public DHPublicKeyParameters(BigInteger bigInteger, DHParameters dHParameters) {
        super(false, dHParameters);
        this.f634y = bigInteger;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof DHPublicKeyParameters)) {
            return false;
        }
        boolean z = ((DHPublicKeyParameters) obj).getY().equals(this.f634y) && super.equals(obj);
        return z;
    }

    public BigInteger getY() {
        return this.f634y;
    }

    public int hashCode() {
        return this.f634y.hashCode() ^ super.hashCode();
    }
}
