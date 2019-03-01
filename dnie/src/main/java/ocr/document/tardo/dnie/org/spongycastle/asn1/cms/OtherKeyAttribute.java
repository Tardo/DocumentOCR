package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class OtherKeyAttribute extends ASN1Encodable {
    private DEREncodable keyAttr;
    private DERObjectIdentifier keyAttrId;

    public static OtherKeyAttribute getInstance(Object o) {
        if (o == null || (o instanceof OtherKeyAttribute)) {
            return (OtherKeyAttribute) o;
        }
        if (o instanceof ASN1Sequence) {
            return new OtherKeyAttribute((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
    }

    public OtherKeyAttribute(ASN1Sequence seq) {
        this.keyAttrId = (DERObjectIdentifier) seq.getObjectAt(0);
        this.keyAttr = seq.getObjectAt(1);
    }

    public OtherKeyAttribute(DERObjectIdentifier keyAttrId, DEREncodable keyAttr) {
        this.keyAttrId = keyAttrId;
        this.keyAttr = keyAttr;
    }

    public DERObjectIdentifier getKeyAttrId() {
        return this.keyAttrId;
    }

    public DEREncodable getKeyAttr() {
        return this.keyAttr;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.keyAttrId);
        v.add(this.keyAttr);
        return new DERSequence(v);
    }
}
