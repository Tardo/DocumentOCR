package org.spongycastle.asn1.pkcs;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class Attribute extends ASN1Encodable {
    private DERObjectIdentifier attrType;
    private ASN1Set attrValues;

    public static Attribute getInstance(Object o) {
        if (o == null || (o instanceof Attribute)) {
            return (Attribute) o;
        }
        if (o instanceof ASN1Sequence) {
            return new Attribute((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
    }

    public Attribute(ASN1Sequence seq) {
        this.attrType = (DERObjectIdentifier) seq.getObjectAt(0);
        this.attrValues = (ASN1Set) seq.getObjectAt(1);
    }

    public Attribute(DERObjectIdentifier attrType, ASN1Set attrValues) {
        this.attrType = attrType;
        this.attrValues = attrValues;
    }

    public DERObjectIdentifier getAttrType() {
        return this.attrType;
    }

    public ASN1Set getAttrValues() {
        return this.attrValues;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.attrType);
        v.add(this.attrValues);
        return new DERSequence(v);
    }
}
