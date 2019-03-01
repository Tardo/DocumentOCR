package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;

public class GOST3410Parameters implements CipherParameters {
    /* renamed from: a */
    private BigInteger f287a;
    /* renamed from: p */
    private BigInteger f288p;
    /* renamed from: q */
    private BigInteger f289q;
    private GOST3410ValidationParameters validation;

    public GOST3410Parameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f288p = bigInteger;
        this.f289q = bigInteger2;
        this.f287a = bigInteger3;
    }

    public GOST3410Parameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, GOST3410ValidationParameters gOST3410ValidationParameters) {
        this.f287a = bigInteger3;
        this.f288p = bigInteger;
        this.f289q = bigInteger2;
        this.validation = gOST3410ValidationParameters;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof GOST3410Parameters)) {
            return false;
        }
        GOST3410Parameters gOST3410Parameters = (GOST3410Parameters) obj;
        return gOST3410Parameters.getP().equals(this.f288p) && gOST3410Parameters.getQ().equals(this.f289q) && gOST3410Parameters.getA().equals(this.f287a);
    }

    public BigInteger getA() {
        return this.f287a;
    }

    public BigInteger getP() {
        return this.f288p;
    }

    public BigInteger getQ() {
        return this.f289q;
    }

    public GOST3410ValidationParameters getValidationParameters() {
        return this.validation;
    }

    public int hashCode() {
        return (this.f288p.hashCode() ^ this.f289q.hashCode()) ^ this.f287a.hashCode();
    }
}
