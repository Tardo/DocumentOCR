package es.gob.jmulticard.card.dnie;

import es.gob.jmulticard.jse.provider.DnieProvider;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

public final class FakeX509Certificate extends X509Certificate {
    private static final long serialVersionUID = 1;
    private final boolean authCert;
    private final Principal issuerDn;
    private final BigInteger serialNumber;
    private final Principal subjectDn;

    public FakeX509Certificate(String subject, String issuer, BigInteger serial, boolean auth) {
        this.subjectDn = new X500Principal(subject);
        this.issuerDn = new X500Principal(issuer);
        this.serialNumber = serial;
        this.authCert = auth;
    }

    public Set getCriticalExtensionOIDs() {
        Set set = new HashSet(2);
        set.add("2.5.29.15");
        set.add("2.5.29.19");
        return set;
    }

    public byte[] getExtensionValue(String e) {
        throw new UnsupportedOperationException();
    }

    public Set getNonCriticalExtensionOIDs() {
        Set set = new HashSet(8);
        set.add("2.5.29.14");
        set.add("2.5.29.9");
        set.add("1.3.6.1.5.5.7.1.1");
        set.add("1.3.6.1.5.5.7.1.2");
        set.add("2.16.724.1.2.2.4.1");
        set.add("2.5.29.32");
        set.add("1.3.6.1.5.5.7.1.3");
        set.add("2.5.29.35");
        return set;
    }

    public boolean hasUnsupportedCriticalExtension() {
        return false;
    }

    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
    }

    public void checkValidity(Date d) throws CertificateExpiredException, CertificateNotYetValidException {
    }

    public int getBasicConstraints() {
        return -1;
    }

    public Principal getIssuerDN() {
        return this.issuerDn;
    }

    public boolean[] getIssuerUniqueID() {
        throw new UnsupportedOperationException();
    }

    public boolean[] getKeyUsage() {
        if (this.authCert) {
            return new boolean[]{true, false, false, false, false, false, false, false, false};
        }
        return new boolean[]{false, true, false, false, false, false, false, false, false};
    }

    public Date getNotAfter() {
        return new Date();
    }

    public Date getNotBefore() {
        return new Date();
    }

    public BigInteger getSerialNumber() {
        return this.serialNumber;
    }

    public String getSigAlgName() {
        return DnieProvider.SHA1WITH_RSA;
    }

    public String getSigAlgOID() {
        return "1.2.840.113549.1.1.5";
    }

    public byte[] getSigAlgParams() {
        return null;
    }

    public byte[] getSignature() {
        throw new UnsupportedOperationException();
    }

    public Principal getSubjectDN() {
        return this.subjectDn;
    }

    public boolean[] getSubjectUniqueID() {
        throw new UnsupportedOperationException();
    }

    public byte[] getTBSCertificate() throws CertificateEncodingException {
        throw new UnsupportedOperationException();
    }

    public int getVersion() {
        return 3;
    }

    public byte[] getEncoded() throws CertificateEncodingException {
        throw new UnsupportedOperationException();
    }

    public PublicKey getPublicKey() {
        throw new UnsupportedOperationException();
    }

    public String toString() {
        return "Certificado impostado: \n Emisor: " + this.issuerDn.toString() + "\n Titular: " + this.subjectDn.toString() + "\n Numero de serie: " + this.serialNumber.toString();
    }

    public void verify(PublicKey puk) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        throw new UnsupportedOperationException();
    }

    public void verify(PublicKey puk, String s) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        throw new UnsupportedOperationException();
    }
}
