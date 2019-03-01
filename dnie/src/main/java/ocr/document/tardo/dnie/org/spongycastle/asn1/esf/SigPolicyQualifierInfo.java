package org.spongycastle.asn1.esf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class SigPolicyQualifierInfo extends ASN1Encodable {
    private DERObjectIdentifier sigPolicyQualifierId;
    private DEREncodable sigQualifier;

    public SigPolicyQualifierInfo(DERObjectIdentifier sigPolicyQualifierId, DEREncodable sigQualifier) {
        this.sigPolicyQualifierId = sigPolicyQualifierId;
        this.sigQualifier = sigQualifier;
    }

    public SigPolicyQualifierInfo(ASN1Sequence seq) {
        this.sigPolicyQualifierId = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.sigQualifier = seq.getObjectAt(1);
    }

    public static SigPolicyQualifierInfo getInstance(Object obj) {
        if (obj == null || (obj instanceof SigPolicyQualifierInfo)) {
            return (SigPolicyQualifierInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new SigPolicyQualifierInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in 'SigPolicyQualifierInfo' factory: " + obj.getClass().getName() + ".");
    }

    public ASN1ObjectIdentifier getSigPolicyQualifierId() {
        return new ASN1ObjectIdentifier(this.sigPolicyQualifierId.getId());
    }

    public DEREncodable getSigQualifier() {
        return this.sigQualifier;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.sigPolicyQualifierId);
        v.add(this.sigQualifier);
        return new DERSequence(v);
    }
}
