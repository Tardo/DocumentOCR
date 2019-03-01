package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class DHPrivateKeyParameters extends DHKeyParameters {
    /* renamed from: x */
    private BigInteger f633x;

    public DHPrivateKeyParameters(BigInteger bigInteger, DHParameters dHParameters) {
        super(true, dHParameters);
        this.f633x = bigInteger;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof DHPrivateKeyParameters)) {
            return false;
        }
        boolean z = ((DHPrivateKeyParameters) obj).getX().equals(this.f633x) && super.equals(obj);
        return z;
    }

    public BigInteger getX() {
        return this.f633x;
    }

    public int hashCode() {
        return this.f633x.hashCode() ^ super.hashCode();
    }
}
