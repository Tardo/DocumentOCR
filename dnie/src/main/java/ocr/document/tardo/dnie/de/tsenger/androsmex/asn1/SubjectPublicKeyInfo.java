package de.tsenger.androsmex.asn1;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class SubjectPublicKeyInfo extends ASN1Encodable {
    private AlgorithmIdentifier algorithm = null;
    private DERBitString subjectPublicKey = null;

    public SubjectPublicKeyInfo(DERSequence seq) {
        this.algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.subjectPublicKey = DERBitString.getInstance(seq.getObjectAt(1));
    }

    public AlgorithmIdentifier getAlgorithm() {
        return this.algorithm;
    }

    public byte[] getPublicKey() {
        return this.subjectPublicKey.getBytes();
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(this.algorithm);
        vec.add(this.subjectPublicKey);
        return new DERSequence(vec);
    }
}
