package org.bouncycastle.asn1;

import java.math.BigInteger;

public class ASN1Enumerated extends DEREnumerated {
    public ASN1Enumerated(int i) {
        super(i);
    }

    public ASN1Enumerated(BigInteger bigInteger) {
        super(bigInteger);
    }

    ASN1Enumerated(byte[] bArr) {
        super(bArr);
    }
}
