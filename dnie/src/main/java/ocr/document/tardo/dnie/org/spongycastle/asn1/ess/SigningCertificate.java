package org.spongycastle.asn1.ess;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.PolicyInformation;

public class SigningCertificate extends ASN1Encodable {
    ASN1Sequence certs;
    ASN1Sequence policies;

    public static SigningCertificate getInstance(Object o) {
        if (o == null || (o instanceof SigningCertificate)) {
            return (SigningCertificate) o;
        }
        if (o instanceof ASN1Sequence) {
            return new SigningCertificate((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in 'SigningCertificate' factory : " + o.getClass().getName() + ".");
    }

    public SigningCertificate(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.certs = ASN1Sequence.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.policies = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    public SigningCertificate(ESSCertID essCertID) {
        this.certs = new DERSequence((DEREncodable) essCertID);
    }

    public ESSCertID[] getCerts() {
        ESSCertID[] cs = new ESSCertID[this.certs.size()];
        for (int i = 0; i != this.certs.size(); i++) {
            cs[i] = ESSCertID.getInstance(this.certs.getObjectAt(i));
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
