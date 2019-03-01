package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class OtherKeyAttribute extends ASN1Object {
    private ASN1Encodable keyAttr;
    private ASN1ObjectIdentifier keyAttrId;

    public OtherKeyAttribute(ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1Encodable aSN1Encodable) {
        this.keyAttrId = aSN1ObjectIdentifier;
        this.keyAttr = aSN1Encodable;
    }

    public OtherKeyAttribute(ASN1Sequence aSN1Sequence) {
        this.keyAttrId = (ASN1ObjectIdentifier) aSN1Sequence.getObjectAt(0);
        this.keyAttr = aSN1Sequence.getObjectAt(1);
    }

    public static OtherKeyAttribute getInstance(Object obj) {
        if (obj == null || (obj instanceof OtherKeyAttribute)) {
            return (OtherKeyAttribute) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new OtherKeyAttribute((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public ASN1Encodable getKeyAttr() {
        return this.keyAttr;
    }

    public ASN1ObjectIdentifier getKeyAttrId() {
        return this.keyAttrId;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(this.keyAttrId);
        aSN1EncodableVector.add(this.keyAttr);
        return new DERSequence(aSN1EncodableVector);
    }
}
