package org.spongycastle.asn1.esf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.ocsp.ResponderID;

public class OcspIdentifier extends ASN1Encodable {
    private ResponderID ocspResponderID;
    private DERGeneralizedTime producedAt;

    public static OcspIdentifier getInstance(Object obj) {
        if (obj instanceof OcspIdentifier) {
            return (OcspIdentifier) obj;
        }
        if (obj != null) {
            return new OcspIdentifier(ASN1Sequence.getInstance(obj));
        }
        throw new IllegalArgumentException("null value in getInstance");
    }

    private OcspIdentifier(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.ocspResponderID = ResponderID.getInstance(seq.getObjectAt(0));
        this.producedAt = (DERGeneralizedTime) seq.getObjectAt(1);
    }

    public OcspIdentifier(ResponderID ocspResponderID, DERGeneralizedTime producedAt) {
        this.ocspResponderID = ocspResponderID;
        this.producedAt = producedAt;
    }

    public ResponderID getOcspResponderID() {
        return this.ocspResponderID;
    }

    public DERGeneralizedTime getProducedAt() {
        return this.producedAt;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.ocspResponderID);
        v.add(this.producedAt);
        return new DERSequence(v);
    }
}
