package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;

public class DSAParameters implements CipherParameters {
    /* renamed from: g */
    private BigInteger f278g;
    /* renamed from: p */
    private BigInteger f279p;
    /* renamed from: q */
    private BigInteger f280q;
    private DSAValidationParameters validation;

    public DSAParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f278g = bigInteger3;
        this.f279p = bigInteger;
        this.f280q = bigInteger2;
    }

    public DSAParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, DSAValidationParameters dSAValidationParameters) {
        this.f278g = bigInteger3;
        this.f279p = bigInteger;
        this.f280q = bigInteger2;
        this.validation = dSAValidationParameters;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof DSAParameters)) {
            return false;
        }
        DSAParameters dSAParameters = (DSAParameters) obj;
        return dSAParameters.getP().equals(this.f279p) && dSAParameters.getQ().equals(this.f280q) && dSAParameters.getG().equals(this.f278g);
    }

    public BigInteger getG() {
        return this.f278g;
    }

    public BigInteger getP() {
        return this.f279p;
    }

    public BigInteger getQ() {
        return this.f280q;
    }

    public DSAValidationParameters getValidationParameters() {
        return this.validation;
    }

    public int hashCode() {
        return (getP().hashCode() ^ getQ().hashCode()) ^ getG().hashCode();
    }
}
