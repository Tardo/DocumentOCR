package org.spongycastle.asn1.ocsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class ResponseBytes extends ASN1Encodable {
    ASN1OctetString response;
    DERObjectIdentifier responseType;

    public ResponseBytes(DERObjectIdentifier responseType, ASN1OctetString response) {
        this.responseType = responseType;
        this.response = response;
    }

    public ResponseBytes(ASN1Sequence seq) {
        this.responseType = (DERObjectIdentifier) seq.getObjectAt(0);
        this.response = (ASN1OctetString) seq.getObjectAt(1);
    }

    public static ResponseBytes getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ResponseBytes getInstance(Object obj) {
        if (obj == null || (obj instanceof ResponseBytes)) {
            return (ResponseBytes) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new ResponseBytes((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public DERObjectIdentifier getResponseType() {
        return this.responseType;
    }

    public ASN1OctetString getResponse() {
        return this.response;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.responseType);
        v.add(this.response);
        return new DERSequence(v);
    }
}
