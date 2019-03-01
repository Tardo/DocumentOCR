package org.spongycastle.asn1.pkcs;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class SafeBag extends ASN1Encodable {
    ASN1Set bagAttributes;
    DERObjectIdentifier bagId;
    DERObject bagValue;

    public SafeBag(DERObjectIdentifier oid, DERObject obj) {
        this.bagId = oid;
        this.bagValue = obj;
        this.bagAttributes = null;
    }

    public SafeBag(DERObjectIdentifier oid, DERObject obj, ASN1Set bagAttributes) {
        this.bagId = oid;
        this.bagValue = obj;
        this.bagAttributes = bagAttributes;
    }

    public SafeBag(ASN1Sequence seq) {
        this.bagId = (DERObjectIdentifier) seq.getObjectAt(0);
        this.bagValue = ((DERTaggedObject) seq.getObjectAt(1)).getObject();
        if (seq.size() == 3) {
            this.bagAttributes = (ASN1Set) seq.getObjectAt(2);
        }
    }

    public DERObjectIdentifier getBagId() {
        return this.bagId;
    }

    public DERObject getBagValue() {
        return this.bagValue;
    }

    public ASN1Set getBagAttributes() {
        return this.bagAttributes;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.bagId);
        v.add(new DERTaggedObject(0, this.bagValue));
        if (this.bagAttributes != null) {
            v.add(this.bagAttributes);
        }
        return new DERSequence(v);
    }
}
