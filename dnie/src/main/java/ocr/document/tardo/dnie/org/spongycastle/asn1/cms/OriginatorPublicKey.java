package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class OriginatorPublicKey extends ASN1Encodable {
    private AlgorithmIdentifier algorithm;
    private DERBitString publicKey;

    public OriginatorPublicKey(AlgorithmIdentifier algorithm, byte[] publicKey) {
        this.algorithm = algorithm;
        this.publicKey = new DERBitString(publicKey);
    }

    public OriginatorPublicKey(ASN1Sequence seq) {
        this.algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.publicKey = (DERBitString) seq.getObjectAt(1);
    }

    public static OriginatorPublicKey getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OriginatorPublicKey getInstance(Object obj) {
        if (obj == null || (obj instanceof OriginatorPublicKey)) {
            return (OriginatorPublicKey) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new OriginatorPublicKey((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid OriginatorPublicKey: " + obj.getClass().getName());
    }

    public AlgorithmIdentifier getAlgorithm() {
        return this.algorithm;
    }

    public DERBitString getPublicKey() {
        return this.publicKey;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.algorithm);
        v.add(this.publicKey);
        return new DERSequence(v);
    }
}
