package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.BERSet;
import org.spongycastle.asn1.DERObject;

public class Attributes extends ASN1Encodable {
    private ASN1Set attributes;

    private Attributes(ASN1Set set) {
        this.attributes = set;
    }

    public Attributes(ASN1EncodableVector v) {
        this.attributes = new BERSet(v);
    }

    public static Attributes getInstance(Object obj) {
        if (obj instanceof Attributes) {
            return (Attributes) obj;
        }
        if (obj != null) {
            return new Attributes(ASN1Set.getInstance(obj));
        }
        return null;
    }

    public DERObject toASN1Object() {
        return this.attributes;
    }
}
