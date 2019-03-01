package org.spongycastle.asn1.isismtt.ocsp;

import java.io.IOException;
import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.X509CertificateStructure;

public class RequestedCertificate extends ASN1Encodable implements ASN1Choice {
    public static final int attributeCertificate = 1;
    public static final int certificate = -1;
    public static final int publicKeyCertificate = 0;
    private byte[] attributeCert;
    private X509CertificateStructure cert;
    private byte[] publicKeyCert;

    public static RequestedCertificate getInstance(Object obj) {
        if (obj == null || (obj instanceof RequestedCertificate)) {
            return (RequestedCertificate) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new RequestedCertificate(X509CertificateStructure.getInstance(obj));
        }
        if (obj instanceof ASN1TaggedObject) {
            return new RequestedCertificate((ASN1TaggedObject) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static RequestedCertificate getInstance(ASN1TaggedObject obj, boolean explicit) {
        if (explicit) {
            return getInstance(obj.getObject());
        }
        throw new IllegalArgumentException("choice item must be explicitly tagged");
    }

    private RequestedCertificate(ASN1TaggedObject tagged) {
        if (tagged.getTagNo() == 0) {
            this.publicKeyCert = ASN1OctetString.getInstance(tagged, true).getOctets();
        } else if (tagged.getTagNo() == 1) {
            this.attributeCert = ASN1OctetString.getInstance(tagged, true).getOctets();
        } else {
            throw new IllegalArgumentException("unknown tag number: " + tagged.getTagNo());
        }
    }

    public RequestedCertificate(X509CertificateStructure certificate) {
        this.cert = certificate;
    }

    public RequestedCertificate(int type, byte[] certificateOctets) {
        this(new DERTaggedObject(type, new DEROctetString(certificateOctets)));
    }

    public int getType() {
        if (this.cert != null) {
            return -1;
        }
        if (this.publicKeyCert != null) {
            return 0;
        }
        return 1;
    }

    public byte[] getCertificateBytes() {
        if (this.cert != null) {
            try {
                return this.cert.getEncoded();
            } catch (IOException e) {
                throw new IllegalStateException("can't decode certificate: " + e);
            }
        } else if (this.publicKeyCert != null) {
            return this.publicKeyCert;
        } else {
            return this.attributeCert;
        }
    }

    public DERObject toASN1Object() {
        if (this.publicKeyCert != null) {
            return new DERTaggedObject(0, new DEROctetString(this.publicKeyCert));
        }
        if (this.attributeCert != null) {
            return new DERTaggedObject(1, new DEROctetString(this.attributeCert));
        }
        return this.cert.getDERObject();
    }
}
