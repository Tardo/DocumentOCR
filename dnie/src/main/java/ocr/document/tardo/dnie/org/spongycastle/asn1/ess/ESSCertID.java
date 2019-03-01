package org.spongycastle.asn1.ess;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.IssuerSerial;

public class ESSCertID extends ASN1Encodable {
    private ASN1OctetString certHash;
    private IssuerSerial issuerSerial;

    public static ESSCertID getInstance(Object o) {
        if (o == null || (o instanceof ESSCertID)) {
            return (ESSCertID) o;
        }
        if (o instanceof ASN1Sequence) {
            return new ESSCertID((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in 'ESSCertID' factory : " + o.getClass().getName() + ".");
    }

    public ESSCertID(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(1));
        }
    }

    public ESSCertID(byte[] hash) {
        this.certHash = new DEROctetString(hash);
    }

    public ESSCertID(byte[] hash, IssuerSerial issuerSerial) {
        this.certHash = new DEROctetString(hash);
        this.issuerSerial = issuerSerial;
    }

    public byte[] getCertHash() {
        return this.certHash.getOctets();
    }

    public IssuerSerial getIssuerSerial() {
        return this.issuerSerial;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.certHash);
        if (this.issuerSerial != null) {
            v.add(this.issuerSerial);
        }
        return new DERSequence(v);
    }
}
