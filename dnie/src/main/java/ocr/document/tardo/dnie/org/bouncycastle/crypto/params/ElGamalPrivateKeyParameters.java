package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class ElGamalPrivateKeyParameters extends ElGamalKeyParameters {
    /* renamed from: x */
    private BigInteger f639x;

    public ElGamalPrivateKeyParameters(BigInteger bigInteger, ElGamalParameters elGamalParameters) {
        super(true, elGamalParameters);
        this.f639x = bigInteger;
    }

    public boolean equals(Object obj) {
        return !(obj instanceof ElGamalPrivateKeyParameters) ? false : !((ElGamalPrivateKeyParameters) obj).getX().equals(this.f639x) ? false : super.equals(obj);
    }

    public BigInteger getX() {
        return this.f639x;
    }

    public int hashCode() {
        return getX().hashCode();
    }
}
