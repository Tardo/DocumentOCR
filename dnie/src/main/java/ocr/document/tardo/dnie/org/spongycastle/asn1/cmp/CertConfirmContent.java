package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;

public class CertConfirmContent extends ASN1Encodable {
    private ASN1Sequence content;

    private CertConfirmContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public static CertConfirmContent getInstance(Object o) {
        if (o instanceof CertConfirmContent) {
            return (CertConfirmContent) o;
        }
        if (o instanceof ASN1Sequence) {
            return new CertConfirmContent((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public CertStatus[] toCertStatusArray() {
        CertStatus[] result = new CertStatus[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = CertStatus.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.content;
    }
}
