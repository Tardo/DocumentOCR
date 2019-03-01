package org.spongycastle.asn1.ocsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREnumerated;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class OCSPResponse extends ASN1Encodable {
    ResponseBytes responseBytes;
    OCSPResponseStatus responseStatus;

    public OCSPResponse(OCSPResponseStatus responseStatus, ResponseBytes responseBytes) {
        this.responseStatus = responseStatus;
        this.responseBytes = responseBytes;
    }

    public OCSPResponse(ASN1Sequence seq) {
        this.responseStatus = new OCSPResponseStatus(DEREnumerated.getInstance(seq.getObjectAt(0)));
        if (seq.size() == 2) {
            this.responseBytes = ResponseBytes.getInstance((ASN1TaggedObject) seq.getObjectAt(1), true);
        }
    }

    public static OCSPResponse getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OCSPResponse getInstance(Object obj) {
        if (obj == null || (obj instanceof OCSPResponse)) {
            return (OCSPResponse) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new OCSPResponse((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public OCSPResponseStatus getResponseStatus() {
        return this.responseStatus;
    }

    public ResponseBytes getResponseBytes() {
        return this.responseBytes;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.responseStatus);
        if (this.responseBytes != null) {
            v.add(new DERTaggedObject(true, 0, this.responseBytes));
        }
        return new DERSequence(v);
    }
}
