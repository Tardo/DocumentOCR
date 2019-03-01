package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;

public class ElGamalParameters implements CipherParameters {
    /* renamed from: g */
    private BigInteger f284g;
    /* renamed from: l */
    private int f285l;
    /* renamed from: p */
    private BigInteger f286p;

    public ElGamalParameters(BigInteger bigInteger, BigInteger bigInteger2) {
        this(bigInteger, bigInteger2, 0);
    }

    public ElGamalParameters(BigInteger bigInteger, BigInteger bigInteger2, int i) {
        this.f284g = bigInteger2;
        this.f286p = bigInteger;
        this.f285l = i;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof ElGamalParameters)) {
            return false;
        }
        ElGamalParameters elGamalParameters = (ElGamalParameters) obj;
        return elGamalParameters.getP().equals(this.f286p) && elGamalParameters.getG().equals(this.f284g) && elGamalParameters.getL() == this.f285l;
    }

    public BigInteger getG() {
        return this.f284g;
    }

    public int getL() {
        return this.f285l;
    }

    public BigInteger getP() {
        return this.f286p;
    }

    public int hashCode() {
        return (getP().hashCode() ^ getG().hashCode()) + this.f285l;
    }
}
