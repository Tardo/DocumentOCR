package org.spongycastle.asn1.ocsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.X509Extensions;

public class TBSRequest extends ASN1Encodable {
    private static final DERInteger V1 = new DERInteger(0);
    X509Extensions requestExtensions;
    ASN1Sequence requestList;
    GeneralName requestorName;
    DERInteger version;
    boolean versionSet;

    public TBSRequest(GeneralName requestorName, ASN1Sequence requestList, X509Extensions requestExtensions) {
        this.version = V1;
        this.requestorName = requestorName;
        this.requestList = requestList;
        this.requestExtensions = requestExtensions;
    }

    public TBSRequest(ASN1Sequence seq) {
        int index;
        int index2 = 0;
        if (!(seq.getObjectAt(0) instanceof ASN1TaggedObject)) {
            this.version = V1;
        } else if (((ASN1TaggedObject) seq.getObjectAt(0)).getTagNo() == 0) {
            this.versionSet = true;
            this.version = DERInteger.getInstance((ASN1TaggedObject) seq.getObjectAt(0), true);
            index2 = 0 + 1;
        } else {
            this.version = V1;
        }
        if (seq.getObjectAt(index2) instanceof ASN1TaggedObject) {
            index = index2 + 1;
            this.requestorName = GeneralName.getInstance((ASN1TaggedObject) seq.getObjectAt(index2), true);
            index2 = index;
        }
        index = index2 + 1;
        this.requestList = (ASN1Sequence) seq.getObjectAt(index2);
        if (seq.size() == index + 1) {
            this.requestExtensions = X509Extensions.getInstance((ASN1TaggedObject) seq.getObjectAt(index), true);
        }
    }

    public static TBSRequest getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static TBSRequest getInstance(Object obj) {
        if (obj == null || (obj instanceof TBSRequest)) {
            return (TBSRequest) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new TBSRequest((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public DERInteger getVersion() {
        return this.version;
    }

    public GeneralName getRequestorName() {
        return this.requestorName;
    }

    public ASN1Sequence getRequestList() {
        return this.requestList;
    }

    public X509Extensions getRequestExtensions() {
        return this.requestExtensions;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (!this.version.equals(V1) || this.versionSet) {
            v.add(new DERTaggedObject(true, 0, this.version));
        }
        if (this.requestorName != null) {
            v.add(new DERTaggedObject(true, 1, this.requestorName));
        }
        v.add(this.requestList);
        if (this.requestExtensions != null) {
            v.add(new DERTaggedObject(true, 2, this.requestExtensions));
        }
        return new DERSequence(v);
    }
}
