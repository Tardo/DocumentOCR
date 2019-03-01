package org.spongycastle.asn1.pkcs;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class CertBag extends ASN1Encodable {
    DERObjectIdentifier certId;
    DERObject certValue;
    ASN1Sequence seq;

    public CertBag(ASN1Sequence seq) {
        this.seq = seq;
        this.certId = (DERObjectIdentifier) seq.getObjectAt(0);
        this.certValue = ((DERTaggedObject) seq.getObjectAt(1)).getObject();
    }

    public CertBag(DERObjectIdentifier certId, DERObject certValue) {
        this.certId = certId;
        this.certValue = certValue;
    }

    public DERObjectIdentifier getCertId() {
        return this.certId;
    }

    public DERObject getCertValue() {
        return this.certValue;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.certId);
        v.add(new DERTaggedObject(0, this.certValue));
        return new DERSequence(v);
    }
}
