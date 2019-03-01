package org.spongycastle.asn1.esf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class SignaturePolicyId extends ASN1Encodable {
    private OtherHashAlgAndValue sigPolicyHash;
    private DERObjectIdentifier sigPolicyId;
    private SigPolicyQualifiers sigPolicyQualifiers;

    public static SignaturePolicyId getInstance(Object obj) {
        if (obj == null || (obj instanceof SignaturePolicyId)) {
            return (SignaturePolicyId) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new SignaturePolicyId((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Unknown object in 'SignaturePolicyId' factory : " + obj.getClass().getName() + ".");
    }

    public SignaturePolicyId(ASN1Sequence seq) {
        if (seq.size() == 2 || seq.size() == 3) {
            this.sigPolicyId = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
            this.sigPolicyHash = OtherHashAlgAndValue.getInstance(seq.getObjectAt(1));
            if (seq.size() == 3) {
                this.sigPolicyQualifiers = SigPolicyQualifiers.getInstance(seq.getObjectAt(2));
                return;
            }
            return;
        }
        throw new IllegalArgumentException("Bad sequence size: " + seq.size());
    }

    public SignaturePolicyId(DERObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash) {
        this(sigPolicyIdentifier, sigPolicyHash, null);
    }

    public SignaturePolicyId(DERObjectIdentifier sigPolicyId, OtherHashAlgAndValue sigPolicyHash, SigPolicyQualifiers sigPolicyQualifiers) {
        this.sigPolicyId = sigPolicyId;
        this.sigPolicyHash = sigPolicyHash;
        this.sigPolicyQualifiers = sigPolicyQualifiers;
    }

    public ASN1ObjectIdentifier getSigPolicyId() {
        return new ASN1ObjectIdentifier(this.sigPolicyId.getId());
    }

    public OtherHashAlgAndValue getSigPolicyHash() {
        return this.sigPolicyHash;
    }

    public SigPolicyQualifiers getSigPolicyQualifiers() {
        return this.sigPolicyQualifiers;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.sigPolicyId);
        v.add(this.sigPolicyHash);
        if (this.sigPolicyQualifiers != null) {
            v.add(this.sigPolicyQualifiers);
        }
        return new DERSequence(v);
    }
}
