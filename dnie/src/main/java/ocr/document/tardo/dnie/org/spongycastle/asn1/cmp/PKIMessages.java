package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class PKIMessages extends ASN1Encodable {
    private ASN1Sequence content;

    private PKIMessages(ASN1Sequence seq) {
        this.content = seq;
    }

    public static PKIMessages getInstance(Object o) {
        if (o instanceof PKIMessages) {
            return (PKIMessages) o;
        }
        if (o instanceof ASN1Sequence) {
            return new PKIMessages((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public PKIMessages(PKIMessage msg) {
        this.content = new DERSequence((DEREncodable) msg);
    }

    public PKIMessages(PKIMessage[] msgs) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (DEREncodable add : msgs) {
            v.add(add);
        }
        this.content = new DERSequence(v);
    }

    public PKIMessage[] toPKIMessageArray() {
        PKIMessage[] result = new PKIMessage[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = PKIMessage.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.content;
    }
}
