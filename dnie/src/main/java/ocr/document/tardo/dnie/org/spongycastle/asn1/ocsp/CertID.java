package org.spongycastle.asn1.ocsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class CertID extends ASN1Encodable {
    AlgorithmIdentifier hashAlgorithm;
    ASN1OctetString issuerKeyHash;
    ASN1OctetString issuerNameHash;
    DERInteger serialNumber;

    public CertID(AlgorithmIdentifier hashAlgorithm, ASN1OctetString issuerNameHash, ASN1OctetString issuerKeyHash, DERInteger serialNumber) {
        this.hashAlgorithm = hashAlgorithm;
        this.issuerNameHash = issuerNameHash;
        this.issuerKeyHash = issuerKeyHash;
        this.serialNumber = serialNumber;
    }

    public CertID(ASN1Sequence seq) {
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.issuerNameHash = (ASN1OctetString) seq.getObjectAt(1);
        this.issuerKeyHash = (ASN1OctetString) seq.getObjectAt(2);
        this.serialNumber = (DERInteger) seq.getObjectAt(3);
    }

    public static CertID getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertID getInstance(Object obj) {
        if (obj == null || (obj instanceof CertID)) {
            return (CertID) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new CertID((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public ASN1OctetString getIssuerNameHash() {
        return this.issuerNameHash;
    }

    public ASN1OctetString getIssuerKeyHash() {
        return this.issuerKeyHash;
    }

    public DERInteger getSerialNumber() {
        return this.serialNumber;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.hashAlgorithm);
        v.add(this.issuerNameHash);
        v.add(this.issuerKeyHash);
        v.add(this.serialNumber);
        return new DERSequence(v);
    }
}
