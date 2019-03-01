package custom.org.apache.harmony.security.provider.cert;

import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.utils.AlgNameMapper;
import custom.org.apache.harmony.security.x509.CertificateList;
import custom.org.apache.harmony.security.x509.Extension;
import custom.org.apache.harmony.security.x509.Extensions;
import custom.org.apache.harmony.security.x509.TBSCertList;
import custom.org.apache.harmony.security.x509.TBSCertList.RevokedCertificate;
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
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

public class X509CRLImpl extends X509CRL {
    private final CertificateList crl;
    private byte[] encoding;
    private ArrayList entries;
    private boolean entriesRetrieved;
    private int entriesSize;
    private final Extensions extensions;
    private boolean isIndirectCRL;
    private X500Principal issuer;
    private int nonIndirectEntriesSize;
    private boolean nullSigAlgParams;
    private String sigAlgName;
    private String sigAlgOID;
    private byte[] sigAlgParams;
    private byte[] signature;
    private final TBSCertList tbsCertList;
    private byte[] tbsCertListEncoding;

    public X509CRLImpl(CertificateList crl) {
        this.crl = crl;
        this.tbsCertList = crl.getTbsCertList();
        this.extensions = this.tbsCertList.getCrlExtensions();
    }

    public X509CRLImpl(InputStream in) throws CRLException {
        try {
            this.crl = (CertificateList) CertificateList.ASN1.decode(in);
            this.tbsCertList = this.crl.getTbsCertList();
            this.extensions = this.tbsCertList.getCrlExtensions();
        } catch (IOException e) {
            throw new CRLException(e);
        }
    }

    public X509CRLImpl(byte[] encoding) throws IOException {
        this((CertificateList) CertificateList.ASN1.decode(encoding));
    }

    public byte[] getEncoded() throws CRLException {
        if (this.encoding == null) {
            this.encoding = this.crl.getEncoded();
        }
        byte[] result = new byte[this.encoding.length];
        System.arraycopy(this.encoding, 0, result, 0, this.encoding.length);
        return result;
    }

    public int getVersion() {
        return this.tbsCertList.getVersion();
    }

    public Principal getIssuerDN() {
        if (this.issuer == null) {
            this.issuer = this.tbsCertList.getIssuer().getX500Principal();
        }
        return this.issuer;
    }

    public X500Principal getIssuerX500Principal() {
        if (this.issuer == null) {
            this.issuer = this.tbsCertList.getIssuer().getX500Principal();
        }
        return this.issuer;
    }

    public Date getThisUpdate() {
        return this.tbsCertList.getThisUpdate();
    }

    public Date getNextUpdate() {
        return this.tbsCertList.getNextUpdate();
    }

    private void retrieveEntries() {
        this.entriesRetrieved = true;
        List rcerts = this.tbsCertList.getRevokedCertificates();
        if (rcerts != null) {
            this.entriesSize = rcerts.size();
            this.entries = new ArrayList(this.entriesSize);
            X500Principal rcertIssuer = null;
            for (int i = 0; i < this.entriesSize; i++) {
                RevokedCertificate rcert = (RevokedCertificate) rcerts.get(i);
                X500Principal iss = rcert.getIssuer();
                if (iss != null) {
                    rcertIssuer = iss;
                    this.isIndirectCRL = true;
                    this.nonIndirectEntriesSize = i;
                }
                this.entries.add(new X509CRLEntryImpl(rcert, rcertIssuer));
            }
        }
    }

    public X509CRLEntry getRevokedCertificate(X509Certificate certificate) {
        if (certificate == null) {
            throw new NullPointerException();
        }
        if (!this.entriesRetrieved) {
            retrieveEntries();
        }
        if (this.entries == null) {
            return null;
        }
        BigInteger serialN = certificate.getSerialNumber();
        int i;
        X509CRLEntry entry;
        if (this.isIndirectCRL) {
            X500Principal certIssuer = certificate.getIssuerX500Principal();
            if (certIssuer.equals(getIssuerX500Principal())) {
                certIssuer = null;
            }
            for (i = 0; i < this.entriesSize; i++) {
                entry = (X509CRLEntry) this.entries.get(i);
                if (serialN.equals(entry.getSerialNumber())) {
                    X500Principal iss = entry.getCertificateIssuer();
                    if (certIssuer != null) {
                        if (certIssuer.equals(iss)) {
                            return entry;
                        }
                    } else if (iss == null) {
                        return entry;
                    }
                }
            }
        } else {
            for (i = 0; i < this.entriesSize; i++) {
                entry = (X509CRLEntry) this.entries.get(i);
                if (serialN.equals(entry.getSerialNumber())) {
                    return entry;
                }
            }
        }
        return null;
    }

    public X509CRLEntry getRevokedCertificate(BigInteger serialNumber) {
        if (!this.entriesRetrieved) {
            retrieveEntries();
        }
        if (this.entries == null) {
            return null;
        }
        for (int i = 0; i < this.nonIndirectEntriesSize; i++) {
            X509CRLEntry entry = (X509CRLEntry) this.entries.get(i);
            if (serialNumber.equals(entry.getSerialNumber())) {
                return entry;
            }
        }
        return null;
    }

    public Set<? extends X509CRLEntry> getRevokedCertificates() {
        if (!this.entriesRetrieved) {
            retrieveEntries();
        }
        if (this.entries == null) {
            return null;
        }
        return new HashSet(this.entries);
    }

    public byte[] getTBSCertList() throws CRLException {
        if (this.tbsCertListEncoding == null) {
            this.tbsCertListEncoding = this.tbsCertList.getEncoded();
        }
        byte[] result = new byte[this.tbsCertListEncoding.length];
        System.arraycopy(this.tbsCertListEncoding, 0, result, 0, this.tbsCertListEncoding.length);
        return result;
    }

    public byte[] getSignature() {
        if (this.signature == null) {
            this.signature = this.crl.getSignatureValue();
        }
        byte[] result = new byte[this.signature.length];
        System.arraycopy(this.signature, 0, result, 0, this.signature.length);
        return result;
    }

    public String getSigAlgName() {
        if (this.sigAlgOID == null) {
            this.sigAlgOID = this.tbsCertList.getSignature().getAlgorithm();
            this.sigAlgName = AlgNameMapper.map2AlgName(this.sigAlgOID);
            if (this.sigAlgName == null) {
                this.sigAlgName = this.sigAlgOID;
            }
        }
        return this.sigAlgName;
    }

    public String getSigAlgOID() {
        if (this.sigAlgOID == null) {
            this.sigAlgOID = this.tbsCertList.getSignature().getAlgorithm();
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
            this.sigAlgParams = this.tbsCertList.getSignature().getParameters();
            if (this.sigAlgParams == null) {
                this.nullSigAlgParams = true;
                return null;
            }
        }
        return this.sigAlgParams;
    }

    public void verify(PublicKey key) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        Signature signature = Signature.getInstance(getSigAlgName());
        signature.initVerify(key);
        byte[] tbsEncoding = this.tbsCertList.getEncoded();
        signature.update(tbsEncoding, 0, tbsEncoding.length);
        if (!signature.verify(this.crl.getSignatureValue())) {
            throw new SignatureException(Messages.getString("security.15C"));
        }
    }

    public void verify(PublicKey key, String sigProvider) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        Signature signature = Signature.getInstance(getSigAlgName(), sigProvider);
        signature.initVerify(key);
        byte[] tbsEncoding = this.tbsCertList.getEncoded();
        signature.update(tbsEncoding, 0, tbsEncoding.length);
        if (!signature.verify(this.crl.getSignatureValue())) {
            throw new SignatureException(Messages.getString("security.15C"));
        }
    }

    public boolean isRevoked(Certificate cert) {
        if ((cert instanceof X509Certificate) && getRevokedCertificate((X509Certificate) cert) != null) {
            return true;
        }
        return false;
    }

    public String toString() {
        return this.crl.toString();
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
