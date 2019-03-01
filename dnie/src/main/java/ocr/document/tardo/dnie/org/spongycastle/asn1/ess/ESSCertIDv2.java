package org.spongycastle.asn1.ess;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.IssuerSerial;

public class ESSCertIDv2 extends ASN1Encodable {
    private static final AlgorithmIdentifier DEFAULT_ALG_ID = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    private byte[] certHash;
    private AlgorithmIdentifier hashAlgorithm;
    private IssuerSerial issuerSerial;

    public static ESSCertIDv2 getInstance(Object o) {
        if (o == null || (o instanceof ESSCertIDv2)) {
            return (ESSCertIDv2) o;
        }
        if (o instanceof ASN1Sequence) {
            return new ESSCertIDv2((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in 'ESSCertIDv2' factory : " + o.getClass().getName() + ".");
    }

    public ESSCertIDv2(ASN1Sequence seq) {
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        int count;
        int count2 = 0;
        if (seq.getObjectAt(0) instanceof ASN1OctetString) {
            this.hashAlgorithm = DEFAULT_ALG_ID;
        } else {
            count = 0 + 1;
            this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0).getDERObject());
            count2 = count;
        }
        count = count2 + 1;
        this.certHash = ASN1OctetString.getInstance(seq.getObjectAt(count2).getDERObject()).getOctets();
        if (seq.size() > count) {
            this.issuerSerial = new IssuerSerial(ASN1Sequence.getInstance(seq.getObjectAt(count).getDERObject()));
        }
    }

    public ESSCertIDv2(AlgorithmIdentifier algId, byte[] certHash) {
        this(algId, certHash, null);
    }

    public ESSCertIDv2(AlgorithmIdentifier algId, byte[] certHash, IssuerSerial issuerSerial) {
        if (algId == null) {
            this.hashAlgorithm = DEFAULT_ALG_ID;
        } else {
            this.hashAlgorithm = algId;
        }
        this.certHash = certHash;
        this.issuerSerial = issuerSerial;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public byte[] getCertHash() {
        return this.certHash;
    }

    public IssuerSerial getIssuerSerial() {
        return this.issuerSerial;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (!this.hashAlgorithm.equals(DEFAULT_ALG_ID)) {
            v.add(this.hashAlgorithm);
        }
        v.add(new DEROctetString(this.certHash).toASN1Object());
        if (this.issuerSerial != null) {
            v.add(this.issuerSerial);
        }
        return new DERSequence(v);
    }
}
