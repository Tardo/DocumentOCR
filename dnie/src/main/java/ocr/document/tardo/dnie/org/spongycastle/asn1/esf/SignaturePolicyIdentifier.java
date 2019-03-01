package org.spongycastle.asn1.esf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Null;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObject;

public class SignaturePolicyIdentifier extends ASN1Encodable {
    private boolean isSignaturePolicyImplied = true;
    private SignaturePolicyId signaturePolicyId;

    public static SignaturePolicyIdentifier getInstance(Object obj) {
        if (obj == null || (obj instanceof SignaturePolicyIdentifier)) {
            return (SignaturePolicyIdentifier) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new SignaturePolicyIdentifier(SignaturePolicyId.getInstance(obj));
        }
        if (obj instanceof ASN1Null) {
            return new SignaturePolicyIdentifier();
        }
        throw new IllegalArgumentException("unknown object in 'SignaturePolicyIdentifier' factory: " + obj.getClass().getName() + ".");
    }

    public SignaturePolicyIdentifier(SignaturePolicyId signaturePolicyId) {
        this.signaturePolicyId = signaturePolicyId;
    }

    public SignaturePolicyId getSignaturePolicyId() {
        return this.signaturePolicyId;
    }

    public boolean isSignaturePolicyImplied() {
        return this.isSignaturePolicyImplied;
    }

    public DERObject toASN1Object() {
        if (this.isSignaturePolicyImplied) {
            return new DERNull();
        }
        return this.signaturePolicyId.getDERObject();
    }
}
