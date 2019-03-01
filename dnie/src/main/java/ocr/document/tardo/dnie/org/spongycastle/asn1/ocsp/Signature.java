package org.spongycastle.asn1.ocsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class Signature extends ASN1Encodable {
    ASN1Sequence certs;
    DERBitString signature;
    AlgorithmIdentifier signatureAlgorithm;

    public Signature(AlgorithmIdentifier signatureAlgorithm, DERBitString signature) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }

    public Signature(AlgorithmIdentifier signatureAlgorithm, DERBitString signature, ASN1Sequence certs) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
        this.certs = certs;
    }

    public Signature(ASN1Sequence seq) {
        this.signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.signature = (DERBitString) seq.getObjectAt(1);
        if (seq.size() == 3) {
            this.certs = ASN1Sequence.getInstance((ASN1TaggedObject) seq.getObjectAt(2), true);
        }
    }

    public static Signature getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Signature getInstance(Object obj) {
        if (obj == null || (obj instanceof Signature)) {
            return (Signature) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new Signature((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public DERBitString getSignature() {
        return this.signature;
    }

    public ASN1Sequence getCerts() {
        return this.certs;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.signatureAlgorithm);
        v.add(this.signature);
        if (this.certs != null) {
            v.add(new DERTaggedObject(true, 0, this.certs));
        }
        return new DERSequence(v);
    }
}
