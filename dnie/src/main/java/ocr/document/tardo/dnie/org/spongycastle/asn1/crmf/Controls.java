package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class Controls extends ASN1Encodable {
    private ASN1Sequence content;

    private Controls(ASN1Sequence seq) {
        this.content = seq;
    }

    public static Controls getInstance(Object o) {
        if (o instanceof Controls) {
            return (Controls) o;
        }
        if (o instanceof ASN1Sequence) {
            return new Controls((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public Controls(AttributeTypeAndValue atv) {
        this.content = new DERSequence((DEREncodable) atv);
    }

    public Controls(AttributeTypeAndValue[] atvs) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (DEREncodable add : atvs) {
            v.add(add);
        }
        this.content = new DERSequence(v);
    }

    public AttributeTypeAndValue[] toAttributeTypeAndValueArray() {
        AttributeTypeAndValue[] result = new AttributeTypeAndValue[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = AttributeTypeAndValue.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.content;
    }
}
