package org.spongycastle.asn1.ocsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.X509Extensions;

public class Request extends ASN1Encodable {
    CertID reqCert;
    X509Extensions singleRequestExtensions;

    public Request(CertID reqCert, X509Extensions singleRequestExtensions) {
        this.reqCert = reqCert;
        this.singleRequestExtensions = singleRequestExtensions;
    }

    public Request(ASN1Sequence seq) {
        this.reqCert = CertID.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2) {
            this.singleRequestExtensions = X509Extensions.getInstance((ASN1TaggedObject) seq.getObjectAt(1), true);
        }
    }

    public static Request getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Request getInstance(Object obj) {
        if (obj == null || (obj instanceof Request)) {
            return (Request) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new Request((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public CertID getReqCert() {
        return this.reqCert;
    }

    public X509Extensions getSingleRequestExtensions() {
        return this.singleRequestExtensions;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.reqCert);
        if (this.singleRequestExtensions != null) {
            v.add(new DERTaggedObject(true, 0, this.singleRequestExtensions));
        }
        return new DERSequence(v);
    }
}
