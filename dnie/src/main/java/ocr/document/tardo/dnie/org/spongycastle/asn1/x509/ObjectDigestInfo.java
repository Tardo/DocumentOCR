package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DEREnumerated;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class ObjectDigestInfo extends ASN1Encodable {
    public static final int otherObjectDigest = 2;
    public static final int publicKey = 0;
    public static final int publicKeyCert = 1;
    AlgorithmIdentifier digestAlgorithm;
    DEREnumerated digestedObjectType;
    DERBitString objectDigest;
    DERObjectIdentifier otherObjectTypeID;

    public static ObjectDigestInfo getInstance(Object obj) {
        if (obj == null || (obj instanceof ObjectDigestInfo)) {
            return (ObjectDigestInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new ObjectDigestInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ObjectDigestInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ObjectDigestInfo(int digestedObjectType, String otherObjectTypeID, AlgorithmIdentifier digestAlgorithm, byte[] objectDigest) {
        this.digestedObjectType = new DEREnumerated(digestedObjectType);
        if (digestedObjectType == 2) {
            this.otherObjectTypeID = new DERObjectIdentifier(otherObjectTypeID);
        }
        this.digestAlgorithm = digestAlgorithm;
        this.objectDigest = new DERBitString(objectDigest);
    }

    private ObjectDigestInfo(ASN1Sequence seq) {
        if (seq.size() > 4 || seq.size() < 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.digestedObjectType = DEREnumerated.getInstance(seq.getObjectAt(0));
        int offset = 0;
        if (seq.size() == 4) {
            this.otherObjectTypeID = DERObjectIdentifier.getInstance(seq.getObjectAt(1));
            offset = 0 + 1;
        }
        this.digestAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(offset + 1));
        this.objectDigest = DERBitString.getInstance(seq.getObjectAt(offset + 2));
    }

    public DEREnumerated getDigestedObjectType() {
        return this.digestedObjectType;
    }

    public DERObjectIdentifier getOtherObjectTypeID() {
        return this.otherObjectTypeID;
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return this.digestAlgorithm;
    }

    public DERBitString getObjectDigest() {
        return this.objectDigest;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.digestedObjectType);
        if (this.otherObjectTypeID != null) {
            v.add(this.otherObjectTypeID);
        }
        v.add(this.digestAlgorithm);
        v.add(this.objectDigest);
        return new DERSequence(v);
    }
}
