package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.x509.CertificateList;

public class CRLAnnContent extends ASN1Encodable {
    private ASN1Sequence content;

    private CRLAnnContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public static CRLAnnContent getInstance(Object o) {
        if (o instanceof CRLAnnContent) {
            return (CRLAnnContent) o;
        }
        if (o instanceof ASN1Sequence) {
            return new CRLAnnContent((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public CertificateList[] toCertificateListArray() {
        CertificateList[] result = new CertificateList[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = CertificateList.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.content;
    }
}
