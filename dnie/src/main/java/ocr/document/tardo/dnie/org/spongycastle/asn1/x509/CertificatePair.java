package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class CertificatePair extends ASN1Encodable {
    private X509CertificateStructure forward;
    private X509CertificateStructure reverse;

    public static CertificatePair getInstance(Object obj) {
        if (obj == null || (obj instanceof CertificatePair)) {
            return (CertificatePair) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new CertificatePair((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private CertificatePair(ASN1Sequence seq) {
        if (seq.size() == 1 || seq.size() == 2) {
            Enumeration e = seq.getObjects();
            while (e.hasMoreElements()) {
                ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
                if (o.getTagNo() == 0) {
                    this.forward = X509CertificateStructure.getInstance(o, true);
                } else if (o.getTagNo() == 1) {
                    this.reverse = X509CertificateStructure.getInstance(o, true);
                } else {
                    throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
                }
            }
            return;
        }
        throw new IllegalArgumentException("Bad sequence size: " + seq.size());
    }

    public CertificatePair(X509CertificateStructure forward, X509CertificateStructure reverse) {
        this.forward = forward;
        this.reverse = reverse;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (this.forward != null) {
            vec.add(new DERTaggedObject(0, this.forward));
        }
        if (this.reverse != null) {
            vec.add(new DERTaggedObject(1, this.reverse));
        }
        return new DERSequence(vec);
    }

    public X509CertificateStructure getForward() {
        return this.forward;
    }

    public X509CertificateStructure getReverse() {
        return this.reverse;
    }
}
