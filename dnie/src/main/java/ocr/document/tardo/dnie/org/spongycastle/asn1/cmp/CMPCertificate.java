package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.AttributeCertificate;
import org.spongycastle.asn1.x509.X509CertificateStructure;

public class CMPCertificate extends ASN1Encodable implements ASN1Choice {
    private AttributeCertificate x509v2AttrCert;
    private X509CertificateStructure x509v3PKCert;

    public CMPCertificate(AttributeCertificate x509v2AttrCert) {
        this.x509v2AttrCert = x509v2AttrCert;
    }

    public CMPCertificate(X509CertificateStructure x509v3PKCert) {
        if (x509v3PKCert.getVersion() != 3) {
            throw new IllegalArgumentException("only version 3 certificates allowed");
        }
        this.x509v3PKCert = x509v3PKCert;
    }

    public static CMPCertificate getInstance(Object o) {
        if (o instanceof CMPCertificate) {
            return (CMPCertificate) o;
        }
        if (o instanceof ASN1Sequence) {
            return new CMPCertificate(X509CertificateStructure.getInstance(o));
        }
        if (o instanceof ASN1TaggedObject) {
            return new CMPCertificate(AttributeCertificate.getInstance(((ASN1TaggedObject) o).getObject()));
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public boolean isX509v3PKCert() {
        return this.x509v3PKCert != null;
    }

    public X509CertificateStructure getX509v3PKCert() {
        return this.x509v3PKCert;
    }

    public AttributeCertificate getX509v2AttrCert() {
        return this.x509v2AttrCert;
    }

    public DERObject toASN1Object() {
        if (this.x509v2AttrCert != null) {
            return new DERTaggedObject(true, 1, this.x509v2AttrCert);
        }
        return this.x509v3PKCert.toASN1Object();
    }
}
