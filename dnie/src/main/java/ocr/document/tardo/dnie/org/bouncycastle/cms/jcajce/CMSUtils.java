package org.bouncycastle.cms.jcajce;

import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;

class CMSUtils {
    CMSUtils() {
    }

    static EnvelopedDataHelper createContentHelper(String str) {
        return str != null ? new EnvelopedDataHelper(new NamedJcaJceExtHelper(str)) : new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    }

    static EnvelopedDataHelper createContentHelper(Provider provider) {
        return provider != null ? new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider)) : new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    }

    static IssuerAndSerialNumber getIssuerAndSerialNumber(X509Certificate x509Certificate) throws CertificateEncodingException {
        return new IssuerAndSerialNumber(Certificate.getInstance(x509Certificate.getEncoded()).getIssuer(), x509Certificate.getSerialNumber());
    }

    static byte[] getSubjectKeyId(X509Certificate x509Certificate) {
        Object extensionValue = x509Certificate.getExtensionValue(X509Extension.subjectKeyIdentifier.getId());
        return extensionValue != null ? ASN1OctetString.getInstance(ASN1OctetString.getInstance(extensionValue).getOctets()).getOctets() : null;
    }

    static TBSCertificateStructure getTBSCertificateStructure(X509Certificate x509Certificate) throws CertificateEncodingException {
        return TBSCertificateStructure.getInstance(x509Certificate.getTBSCertificate());
    }
}
