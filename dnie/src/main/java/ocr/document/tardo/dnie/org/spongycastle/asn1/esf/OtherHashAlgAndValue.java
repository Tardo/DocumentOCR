package org.spongycastle.asn1.esf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class OtherHashAlgAndValue extends ASN1Encodable {
    private AlgorithmIdentifier hashAlgorithm;
    private ASN1OctetString hashValue;

    public static OtherHashAlgAndValue getInstance(Object obj) {
        if (obj instanceof OtherHashAlgAndValue) {
            return (OtherHashAlgAndValue) obj;
        }
        if (obj != null) {
            return new OtherHashAlgAndValue(ASN1Sequence.getInstance(obj));
        }
        throw new IllegalArgumentException("null value in getInstance");
    }

    private OtherHashAlgAndValue(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.hashValue = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public OtherHashAlgAndValue(AlgorithmIdentifier hashAlgorithm, ASN1OctetString hashValue) {
        this.hashAlgorithm = hashAlgorithm;
        this.hashValue = hashValue;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public ASN1OctetString getHashValue() {
        return this.hashValue;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.hashAlgorithm);
        v.add(this.hashValue);
        return new DERSequence(v);
    }
}
