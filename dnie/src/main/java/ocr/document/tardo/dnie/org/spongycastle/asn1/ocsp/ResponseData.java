package org.spongycastle.asn1.ocsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.X509Extensions;

public class ResponseData extends ASN1Encodable {
    private static final DERInteger V1 = new DERInteger(0);
    private DERGeneralizedTime producedAt;
    private ResponderID responderID;
    private X509Extensions responseExtensions;
    private ASN1Sequence responses;
    private DERInteger version;
    private boolean versionPresent;

    public ResponseData(DERInteger version, ResponderID responderID, DERGeneralizedTime producedAt, ASN1Sequence responses, X509Extensions responseExtensions) {
        this.version = version;
        this.responderID = responderID;
        this.producedAt = producedAt;
        this.responses = responses;
        this.responseExtensions = responseExtensions;
    }

    public ResponseData(ResponderID responderID, DERGeneralizedTime producedAt, ASN1Sequence responses, X509Extensions responseExtensions) {
        this(V1, responderID, producedAt, responses, responseExtensions);
    }

    public ResponseData(ASN1Sequence seq) {
        int index = 0;
        if (!(seq.getObjectAt(0) instanceof ASN1TaggedObject)) {
            this.version = V1;
        } else if (((ASN1TaggedObject) seq.getObjectAt(0)).getTagNo() == 0) {
            this.versionPresent = true;
            this.version = DERInteger.getInstance((ASN1TaggedObject) seq.getObjectAt(0), true);
            index = 0 + 1;
        } else {
            this.version = V1;
        }
        int index2 = index + 1;
        this.responderID = ResponderID.getInstance(seq.getObjectAt(index));
        index = index2 + 1;
        this.producedAt = (DERGeneralizedTime) seq.getObjectAt(index2);
        index2 = index + 1;
        this.responses = (ASN1Sequence) seq.getObjectAt(index);
        if (seq.size() > index2) {
            this.responseExtensions = X509Extensions.getInstance((ASN1TaggedObject) seq.getObjectAt(index2), true);
        }
    }

    public static ResponseData getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ResponseData getInstance(Object obj) {
        if (obj == null || (obj instanceof ResponseData)) {
            return (ResponseData) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new ResponseData((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public DERInteger getVersion() {
        return this.version;
    }

    public ResponderID getResponderID() {
        return this.responderID;
    }

    public DERGeneralizedTime getProducedAt() {
        return this.producedAt;
    }

    public ASN1Sequence getResponses() {
        return this.responses;
    }

    public X509Extensions getResponseExtensions() {
        return this.responseExtensions;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.versionPresent || !this.version.equals(V1)) {
            v.add(new DERTaggedObject(true, 0, this.version));
        }
        v.add(this.responderID);
        v.add(this.producedAt);
        v.add(this.responses);
        if (this.responseExtensions != null) {
            v.add(new DERTaggedObject(true, 1, this.responseExtensions));
        }
        return new DERSequence(v);
    }
}
