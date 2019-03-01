package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class CertReqMessages extends ASN1Encodable {
    private ASN1Sequence content;

    private CertReqMessages(ASN1Sequence seq) {
        this.content = seq;
    }

    public static CertReqMessages getInstance(Object o) {
        if (o instanceof CertReqMessages) {
            return (CertReqMessages) o;
        }
        if (o instanceof ASN1Sequence) {
            return new CertReqMessages((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public CertReqMessages(CertReqMsg msg) {
        this.content = new DERSequence((DEREncodable) msg);
    }

    public CertReqMessages(CertReqMsg[] msgs) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (DEREncodable add : msgs) {
            v.add(add);
        }
        this.content = new DERSequence(v);
    }

    public CertReqMsg[] toCertReqMsgArray() {
        CertReqMsg[] result = new CertReqMsg[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = CertReqMsg.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.content;
    }
}
