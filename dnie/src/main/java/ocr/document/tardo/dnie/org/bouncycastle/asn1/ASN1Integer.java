package org.bouncycastle.asn1;

import java.math.BigInteger;

public class ASN1Integer extends DERInteger {
    public ASN1Integer(long j) {
        super(j);
    }

    public ASN1Integer(BigInteger bigInteger) {
        super(bigInteger);
    }

    ASN1Integer(byte[] bArr) {
        super(bArr);
    }
}
