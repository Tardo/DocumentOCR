package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class GenMsgContent extends ASN1Encodable {
    private ASN1Sequence content;

    private GenMsgContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public static GenMsgContent getInstance(Object o) {
        if (o instanceof GenMsgContent) {
            return (GenMsgContent) o;
        }
        if (o instanceof ASN1Sequence) {
            return new GenMsgContent((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public GenMsgContent(InfoTypeAndValue itv) {
        this.content = new DERSequence((DEREncodable) itv);
    }

    public GenMsgContent(InfoTypeAndValue[] itv) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (DEREncodable add : itv) {
            v.add(add);
        }
        this.content = new DERSequence(v);
    }

    public InfoTypeAndValue[] toInfoTypeAndValueArray() {
        InfoTypeAndValue[] result = new InfoTypeAndValue[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = InfoTypeAndValue.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.content;
    }
}
