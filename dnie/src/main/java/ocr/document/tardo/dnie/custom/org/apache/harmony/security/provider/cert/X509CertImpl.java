package custom.org.apache.harmony.security.provider.cert;

import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.utils.AlgNameMapper;
import custom.org.apache.harmony.security.x509.Certificate;
import custom.org.apache.harmony.security.x509.Extension;
import custom.org.apache.harmony.security.x509.Extensions;
import custom.org.apache.harmony.security.x509.TBSCertificate;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

public class X509CertImpl extends X509Certificate {
    private static final long serialVersionUID = 2972248729446736154L;
    private final Certificate certificate;
    private byte[] encoding;
    private final Extensions extensions;
    private X500Principal issuer;
    private long notAfter;
    private long notBefore;
    private boolean nullSigAlgParams;
    private PublicKey publicKey;
    private BigInteger serialNumber;
    private String sigAlgName;
    private String sigAlgOID;
    private byte[] sigAlgParams;
    private byte[] signature;
    private X500Principal subject;
    private final TBSCertificate tbsCert;
    private byte[] tbsCertificate;

    public X509CertImpl(InputStream in) throws CertificateException {
        this.notBefore = -1;
        try {
            this.certificate = (Certificate) Certificate.ASN1.decode(in);
            this.tbsCert = this.certificate.getTbsCertificate();
            this.extensions = this.tbsCert.getExtensions();
        } catch (IOException e) {
            throw new CertificateException(e);
        }
    }

    public X509CertImpl(Certificate certificate) {
        this.notBefore = -1;
        this.certificate = certificate;
        this.tbsCert = certificate.getTbsCertificate();
        this.extensions = this.tbsCert.getExtensions();
    }

    public X509CertImpl(byte[] encoding) throws IOException {
        this((Certificate) Certificate.ASN1.decode(encoding));
    }

    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        if (this.notBefore == -1) {
            this.notBefore = this.tbsCert.getValidity().getNotBefore().getTime();
            this.notAfter = this.tbsCert.getValidity().getNotAfter().getTime();
        }
        long time = System.currentTimeMillis();
        if (time < this.notBefore) {
            throw new CertificateNotYetValidException();
        } else if (time > this.notAfter) {
            throw new CertificateExpiredException();
        }
    }

    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        if (this.notBefore == -1) {
            this.notBefore = this.tbsCert.getValidity().getNotBefore().getTime();
            this.notAfter = this.tbsCert.getValidity().getNotAfter().getTime();
        }
        long time = date.getTime();
        if (time < this.notBefore) {
            throw new CertificateNotYetValidException();
        } else if (time > this.notAfter) {
            throw new CertificateExpiredException();
        }
    }

    public int getVersion() {
        return this.tbsCert.getVersion() + 1;
    }

    public BigInteger getSerialNumber() {
        if (this.serialNumber == null) {
            this.serialNumber = this.tbsCert.getSerialNumber();
        }
        return this.serialNumber;
    }

    public Principal getIssuerDN() {
        if (this.issuer == null) {
            this.issuer = this.tbsCert.getIssuer().getX500Principal();
        }
        return this.issuer;
    }

    public X500Principal getIssuerX500Principal() {
        if (this.issuer == null) {
            this.issuer = this.tbsCert.getIssuer().getX500Principal();
        }
        return this.issuer;
    }

    public Principal getSubjectDN() {
        if (this.subject == null) {
            this.subject = this.tbsCert.getSubject().getX500Principal();
        }
        return this.subject;
    }

    public X500Principal getSubjectX500Principal() {
        if (this.subject == null) {
            this.subject = this.tbsCert.getSubject().getX500Principal();
        }
        return this.subject;
    }

    public Date getNotBefore() {
        if (this.notBefore == -1) {
            this.notBefore = this.tbsCert.getValidity().getNotBefore().getTime();
            this.notAfter = this.tbsCert.getValidity().getNotAfter().getTime();
        }
        return new Date(this.notBefore);
    }

    public Date getNotAfter() {
        if (this.notBefore == -1) {
            this.notBefore = this.tbsCert.getValidity().getNotBefore().getTime();
            this.notAfter = this.tbsCert.getValidity().getNotAfter().getTime();
        }
        return new Date(this.notAfter);
    }

    public byte[] getTBSCertificate() throws CertificateEncodingException {
        if (this.tbsCertificate == null) {
            this.tbsCertificate = this.tbsCert.getEncoded();
        }
        byte[] result = new byte[this.tbsCertificate.length];
        System.arraycopy(this.tbsCertificate, 0, result, 0, this.tbsCertificate.length);
        return result;
    }

    public byte[] getSignature() {
        if (this.signature == null) {
            this.signature = this.certificate.getSignatureValue();
        }
        byte[] result = new byte[this.signature.length];
        System.arraycopy(this.signature, 0, result, 0, this.signature.length);
        return result;
    }

    public String getSigAlgName() {
        if (this.sigAlgOID == null) {
            this.sigAlgOID = this.tbsCert.getSignature().getAlgorithm();
            this.sigAlgName = AlgNameMapper.map2AlgName(this.sigAlgOID);
            if (this.sigAlgName == null) {
                this.sigAlgName = this.sigAlgOID;
            }
        }
        return this.sigAlgName;
    }

    public String getSigAlgOID() {
        if (this.sigAlgOID == null) {
            this.sigAlgOID = this.tbsCert.getSignature().getAlgorithm();
            this.sigAlgName = AlgNameMapper.map2AlgName(this.sigAlgOID);
            if (this.sigAlgName == null) {
                this.sigAlgName = this.sigAlgOID;
            }
        }
        return this.sigAlgOID;
    }

    public byte[] getSigAlgParams() {
        if (this.nullSigAlgParams) {
            return null;
        }
        if (this.sigAlgParams == null) {
            this.sigAlgParams = this.tbsCert.getSignature().getParameters();
            if (this.sigAlgParams == null) {
                this.nullSigAlgParams = true;
                return null;
            }
        }
        return this.sigAlgParams;
    }

    public boolean[] getIssuerUniqueID() {
        return this.tbsCert.getIssuerUniqueID();
    }

    public boolean[] getSubjectUniqueID() {
        return this.tbsCert.getSubjectUniqueID();
    }

    public boolean[] getKeyUsage() {
        if (this.extensions == null) {
            return null;
        }
        return this.extensions.valueOfKeyUsage();
    }

    public List getExtendedKeyUsage() throws CertificateParsingException {
        if (this.extensions == null) {
            return null;
        }
        try {
            return this.extensions.valueOfExtendedKeyUsage();
        } catch (IOException e) {
            throw new CertificateParsingException(e);
        }
    }

    public int getBasicConstraints() {
        if (this.extensions == null) {
            return Integer.MAX_VALUE;
        }
        return this.extensions.valueOfBasicConstrains();
    }

    public Collection getSubjectAlternativeNames() throws CertificateParsingException {
        if (this.extensions == null) {
            return null;
        }
        try {
            return this.extensions.valueOfSubjectAlternativeName();
        } catch (IOException e) {
            throw new CertificateParsingException(e);
        }
    }

    public Collection getIssuerAlternativeNames() throws CertificateParsingException {
        if (this.extensions == null) {
            return null;
        }
        try {
            return this.extensions.valueOfIssuerAlternativeName();
        } catch (IOException e) {
            throw new CertificateParsingException(e);
        }
    }

    public byte[] getEncoded() throws CertificateEncodingException {
        if (this.encoding == null) {
            this.encoding = this.certificate.getEncoded();
        }
        byte[] result = new byte[this.encoding.length];
        System.arraycopy(this.encoding, 0, result, 0, this.encoding.length);
        return result;
    }

    public PublicKey getPublicKey() {
        if (this.publicKey == null) {
            this.publicKey = this.tbsCert.getSubjectPublicKeyInfo().getPublicKey();
        }
        return this.publicKey;
    }

    public String toString() {
        return this.certificate.toString();
    }

    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        Signature signature = Signature.getInstance(getSigAlgName());
        signature.initVerify(key);
        if (this.tbsCertificate == null) {
            this.tbsCertificate = this.tbsCert.getEncoded();
        }
        signature.update(this.tbsCertificate, 0, this.tbsCertificate.length);
        if (!signature.verify(this.certificate.getSignatureValue())) {
            throw new SignatureException(Messages.getString("security.15C"));
        }
    }

    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        Signature signature = Signature.getInstance(getSigAlgName(), sigProvider);
        signature.initVerify(key);
        if (this.tbsCertificate == null) {
            this.tbsCertificate = this.tbsCert.getEncoded();
        }
        signature.update(this.tbsCertificate, 0, this.tbsCertificate.length);
        if (!signature.verify(this.certificate.getSignatureValue())) {
            throw new SignatureException(Messages.getString("security.15C"));
        }
    }

    public Set getNonCriticalExtensionOIDs() {
        if (this.extensions == null) {
            return null;
        }
        return this.extensions.getNonCriticalExtensions();
    }

    public Set getCriticalExtensionOIDs() {
        if (this.extensions == null) {
            return null;
        }
        return this.extensions.getCriticalExtensions();
    }

    public byte[] getExtensionValue(String oid) {
        if (this.extensions == null) {
            return null;
        }
        Extension ext = this.extensions.getExtensionByOID(oid);
        if (ext != null) {
            return ext.getRawExtnValue();
        }
        return null;
    }

    public boolean hasUnsupportedCriticalExtension() {
        if (this.extensions == null) {
            return false;
        }
        return this.extensions.hasUnsupportedCritical();
    }
}
