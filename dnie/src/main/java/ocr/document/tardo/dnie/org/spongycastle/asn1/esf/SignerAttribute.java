package org.spongycastle.asn1.esf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.AttributeCertificate;

public class SignerAttribute extends ASN1Encodable {
    private AttributeCertificate certifiedAttributes;
    private ASN1Sequence claimedAttributes;

    public static SignerAttribute getInstance(Object o) {
        if (o == null || (o instanceof SignerAttribute)) {
            return (SignerAttribute) o;
        }
        if (o instanceof ASN1Sequence) {
            return new SignerAttribute(o);
        }
        throw new IllegalArgumentException("unknown object in 'SignerAttribute' factory: " + o.getClass().getName() + ".");
    }

    private SignerAttribute(Object o) {
        DERTaggedObject taggedObject = (DERTaggedObject) ((ASN1Sequence) o).getObjectAt(0);
        if (taggedObject.getTagNo() == 0) {
            this.claimedAttributes = ASN1Sequence.getInstance(taggedObject, true);
        } else if (taggedObject.getTagNo() == 1) {
            this.certifiedAttributes = AttributeCertificate.getInstance(taggedObject);
        } else {
            throw new IllegalArgumentException("illegal tag.");
        }
    }

    public SignerAttribute(ASN1Sequence claimedAttributes) {
        this.claimedAttributes = claimedAttributes;
    }

    public SignerAttribute(AttributeCertificate certifiedAttributes) {
        this.certifiedAttributes = certifiedAttributes;
    }

    public ASN1Sequence getClaimedAttributes() {
        return this.claimedAttributes;
    }

    public AttributeCertificate getCertifiedAttributes() {
        return this.certifiedAttributes;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.claimedAttributes != null) {
            v.add(new DERTaggedObject(0, this.claimedAttributes));
        } else {
            v.add(new DERTaggedObject(1, this.certifiedAttributes));
        }
        return new DERSequence(v);
    }
}
