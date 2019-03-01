package org.spongycastle.asn1.ess;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.PolicyInformation;

public class OtherSigningCertificate extends ASN1Encodable {
    ASN1Sequence certs;
    ASN1Sequence policies;

    public static OtherSigningCertificate getInstance(Object o) {
        if (o == null || (o instanceof OtherSigningCertificate)) {
            return (OtherSigningCertificate) o;
        }
        if (o instanceof ASN1Sequence) {
            return new OtherSigningCertificate((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in 'OtherSigningCertificate' factory : " + o.getClass().getName() + ".");
    }

    public OtherSigningCertificate(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.certs = ASN1Sequence.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.policies = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    public OtherSigningCertificate(OtherCertID otherCertID) {
        this.certs = new DERSequence((DEREncodable) otherCertID);
    }

    public OtherCertID[] getCerts() {
        OtherCertID[] cs = new OtherCertID[this.certs.size()];
        for (int i = 0; i != this.certs.size(); i++) {
            cs[i] = OtherCertID.getInstance(this.certs.getObjectAt(i));
        }
        return cs;
    }

    public PolicyInformation[] getPolicies() {
        if (this.policies == null) {
            return null;
        }
        PolicyInformation[] ps = new PolicyInformation[this.policies.size()];
        for (int i = 0; i != this.policies.size(); i++) {
            ps[i] = PolicyInformation.getInstance(this.policies.getObjectAt(i));
        }
        return ps;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.certs);
        if (this.policies != null) {
            v.add(this.policies);
        }
        return new DERSequence(v);
    }
}
