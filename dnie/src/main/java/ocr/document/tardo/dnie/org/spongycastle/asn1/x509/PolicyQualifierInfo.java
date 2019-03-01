package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class PolicyQualifierInfo extends ASN1Encodable {
    private DERObjectIdentifier policyQualifierId;
    private DEREncodable qualifier;

    public PolicyQualifierInfo(DERObjectIdentifier policyQualifierId, DEREncodable qualifier) {
        this.policyQualifierId = policyQualifierId;
        this.qualifier = qualifier;
    }

    public PolicyQualifierInfo(String cps) {
        this.policyQualifierId = PolicyQualifierId.id_qt_cps;
        this.qualifier = new DERIA5String(cps);
    }

    public PolicyQualifierInfo(ASN1Sequence as) {
        if (as.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
        }
        this.policyQualifierId = DERObjectIdentifier.getInstance(as.getObjectAt(0));
        this.qualifier = as.getObjectAt(1);
    }

    public static PolicyQualifierInfo getInstance(Object as) {
        if (as instanceof PolicyQualifierInfo) {
            return (PolicyQualifierInfo) as;
        }
        if (as instanceof ASN1Sequence) {
            return new PolicyQualifierInfo((ASN1Sequence) as);
        }
        throw new IllegalArgumentException("unknown object in getInstance.");
    }

    public DERObjectIdentifier getPolicyQualifierId() {
        return this.policyQualifierId;
    }

    public DEREncodable getQualifier() {
        return this.qualifier;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector dev = new ASN1EncodableVector();
        dev.add(this.policyQualifierId);
        dev.add(this.qualifier);
        return new DERSequence(dev);
    }
}
