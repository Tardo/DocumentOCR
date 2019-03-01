package org.spongycastle.jce;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.x509.TBSCertList;
import org.spongycastle.asn1.x509.TBSCertificateStructure;

public class PrincipalUtil {
    public static X509Principal getIssuerX509Principal(X509Certificate cert) throws CertificateEncodingException {
        try {
            return new X509Principal(TBSCertificateStructure.getInstance(ASN1Object.fromByteArray(cert.getTBSCertificate())).getIssuer());
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public static X509Principal getSubjectX509Principal(X509Certificate cert) throws CertificateEncodingException {
        try {
            return new X509Principal(TBSCertificateStructure.getInstance(ASN1Object.fromByteArray(cert.getTBSCertificate())).getSubject());
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public static X509Principal getIssuerX509Principal(X509CRL crl) throws CRLException {
        try {
            return new X509Principal(TBSCertList.getInstance(ASN1Object.fromByteArray(crl.getTBSCertList())).getIssuer());
        } catch (IOException e) {
            throw new CRLException(e.toString());
        }
    }
}
