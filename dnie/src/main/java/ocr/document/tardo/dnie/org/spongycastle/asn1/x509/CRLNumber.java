package org.spongycastle.asn1.x509;

import java.math.BigInteger;
import org.spongycastle.asn1.DERInteger;

public class CRLNumber extends DERInteger {
    public CRLNumber(BigInteger number) {
        super(number);
    }

    public BigInteger getCRLNumber() {
        return getPositiveValue();
    }

    public String toString() {
        return "CRLNumber: " + getCRLNumber();
    }
}
