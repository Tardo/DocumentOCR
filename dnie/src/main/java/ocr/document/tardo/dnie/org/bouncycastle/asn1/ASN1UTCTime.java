package org.bouncycastle.asn1;

import java.util.Date;

public class ASN1UTCTime extends DERUTCTime {
    public ASN1UTCTime(String str) {
        super(str);
    }

    public ASN1UTCTime(Date date) {
        super(date);
    }

    ASN1UTCTime(byte[] bArr) {
        super(bArr);
    }
}
