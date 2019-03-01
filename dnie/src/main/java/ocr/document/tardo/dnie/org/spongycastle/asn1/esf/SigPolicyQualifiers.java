package org.spongycastle.asn1.esf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class SigPolicyQualifiers extends ASN1Encodable {
    ASN1Sequence qualifiers;

    public static SigPolicyQualifiers getInstance(Object obj) {
        if (obj instanceof SigPolicyQualifiers) {
            return (SigPolicyQualifiers) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new SigPolicyQualifiers((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in 'SigPolicyQualifiers' factory: " + obj.getClass().getName() + ".");
    }

    public SigPolicyQualifiers(ASN1Sequence seq) {
        this.qualifiers = seq;
    }

    public SigPolicyQualifiers(SigPolicyQualifierInfo[] qualifierInfos) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (DEREncodable add : qualifierInfos) {
            v.add(add);
        }
        this.qualifiers = new DERSequence(v);
    }

    public int size() {
        return this.qualifiers.size();
    }

    public SigPolicyQualifierInfo getStringAt(int i) {
        return SigPolicyQualifierInfo.getInstance(this.qualifiers.getObjectAt(i));
    }

    public DERObject toASN1Object() {
        return this.qualifiers;
    }
}
