package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class ElGamalPublicKeyParameters extends ElGamalKeyParameters {
    /* renamed from: y */
    private BigInteger f640y;

    public ElGamalPublicKeyParameters(BigInteger bigInteger, ElGamalParameters elGamalParameters) {
        super(false, elGamalParameters);
        this.f640y = bigInteger;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof ElGamalPublicKeyParameters)) {
            return false;
        }
        boolean z = ((ElGamalPublicKeyParameters) obj).getY().equals(this.f640y) && super.equals(obj);
        return z;
    }

    public BigInteger getY() {
        return this.f640y;
    }

    public int hashCode() {
        return this.f640y.hashCode() ^ super.hashCode();
    }
}
