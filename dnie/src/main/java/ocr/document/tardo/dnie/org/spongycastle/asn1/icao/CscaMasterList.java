package org.spongycastle.asn1.icao;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.x509.X509CertificateStructure;

public class CscaMasterList extends ASN1Encodable {
    private X509CertificateStructure[] certList;
    private DERInteger version = new DERInteger(0);

    public static CscaMasterList getInstance(Object obj) {
        if (obj instanceof CscaMasterList) {
            return (CscaMasterList) obj;
        }
        if (obj != null) {
            return new CscaMasterList(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private CscaMasterList(ASN1Sequence seq) {
        if (seq == null || seq.size() == 0) {
            throw new IllegalArgumentException("null or empty sequence passed.");
        } else if (seq.size() != 2) {
            throw new IllegalArgumentException("Incorrect sequence size: " + seq.size());
        } else {
            this.version = DERInteger.getInstance(seq.getObjectAt(0));
            ASN1Set certSet = ASN1Set.getInstance(seq.getObjectAt(1));
            this.certList = new X509CertificateStructure[certSet.size()];
            for (int i = 0; i < this.certList.length; i++) {
                this.certList[i] = X509CertificateStructure.getInstance(certSet.getObjectAt(i));
            }
        }
    }

    public CscaMasterList(X509CertificateStructure[] certStructs) {
        this.certList = copyCertList(certStructs);
    }

    public int getVersion() {
        return this.version.getValue().intValue();
    }

    public X509CertificateStructure[] getCertStructs() {
        return copyCertList(this.certList);
    }

    private X509CertificateStructure[] copyCertList(X509CertificateStructure[] orig) {
        X509CertificateStructure[] certs = new X509CertificateStructure[orig.length];
        for (int i = 0; i != certs.length; i++) {
            certs[i] = orig[i];
        }
        return certs;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(this.version);
        ASN1EncodableVector certSet = new ASN1EncodableVector();
        for (DEREncodable add : this.certList) {
            certSet.add(add);
        }
        seq.add(new DERSet(certSet));
        return new DERSequence(seq);
    }
}
