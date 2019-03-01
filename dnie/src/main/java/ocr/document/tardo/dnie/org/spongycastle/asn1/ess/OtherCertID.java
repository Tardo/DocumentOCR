package org.spongycastle.asn1.ess;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.DigestInfo;
import org.spongycastle.asn1.x509.IssuerSerial;

public class OtherCertID extends ASN1Encodable {
    private IssuerSerial issuerSerial;
    private ASN1Encodable otherCertHash;

    public static OtherCertID getInstance(Object o) {
        if (o == null || (o instanceof OtherCertID)) {
            return (OtherCertID) o;
        }
        if (o instanceof ASN1Sequence) {
            return new OtherCertID((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in 'OtherCertID' factory : " + o.getClass().getName() + ".");
    }

    public OtherCertID(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        if (seq.getObjectAt(0).getDERObject() instanceof ASN1OctetString) {
            this.otherCertHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        } else {
            this.otherCertHash = DigestInfo.getInstance(seq.getObjectAt(0));
        }
        if (seq.size() > 1) {
            this.issuerSerial = new IssuerSerial(ASN1Sequence.getInstance(seq.getObjectAt(1)));
        }
    }

    public OtherCertID(AlgorithmIdentifier algId, byte[] digest) {
        this.otherCertHash = new DigestInfo(algId, digest);
    }

    public OtherCertID(AlgorithmIdentifier algId, byte[] digest, IssuerSerial issuerSerial) {
        this.otherCertHash = new DigestInfo(algId, digest);
        this.issuerSerial = issuerSerial;
    }

    public AlgorithmIdentifier getAlgorithmHash() {
        if (this.otherCertHash.getDERObject() instanceof ASN1OctetString) {
            return new AlgorithmIdentifier("1.3.14.3.2.26");
        }
        return DigestInfo.getInstance(this.otherCertHash).getAlgorithmId();
    }

    public byte[] getCertHash() {
        if (this.otherCertHash.getDERObject() instanceof ASN1OctetString) {
            return ((ASN1OctetString) this.otherCertHash.getDERObject()).getOctets();
        }
        return DigestInfo.getInstance(this.otherCertHash).getDigest();
    }

    public IssuerSerial getIssuerSerial() {
        return this.issuerSerial;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.otherCertHash);
        if (this.issuerSerial != null) {
            v.add(this.issuerSerial);
        }
        return new DERSequence(v);
    }
}
