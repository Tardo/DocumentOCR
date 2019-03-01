package org.spongycastle.jce.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1OutputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.util.ASN1Dump;
import org.spongycastle.asn1.x509.CRLDistPoint;
import org.spongycastle.asn1.x509.CRLNumber;
import org.spongycastle.asn1.x509.CertificateList;
import org.spongycastle.asn1.x509.IssuingDistributionPoint;
import org.spongycastle.asn1.x509.TBSCertList.CRLEntry;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.asn1.x509.X509Extensions;
import org.spongycastle.jce.X509Principal;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.x509.extension.X509ExtensionUtil;

public class X509CRLObject extends X509CRL {
    /* renamed from: c */
    private CertificateList f180c;
    private boolean isIndirect;
    private String sigAlgName;
    private byte[] sigAlgParams;

    public X509CRLObject(CertificateList c) throws CRLException {
        this.f180c = c;
        try {
            this.sigAlgName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());
            if (c.getSignatureAlgorithm().getParameters() != null) {
                this.sigAlgParams = ((ASN1Encodable) c.getSignatureAlgorithm().getParameters()).getDEREncoded();
            } else {
                this.sigAlgParams = null;
            }
            this.isIndirect = isIndirectCRL();
        } catch (Exception e) {
            throw new CRLException("CRL contents invalid: " + e);
        }
    }

    public boolean hasUnsupportedCriticalExtension() {
        Set extns = getCriticalExtensionOIDs();
        if (extns == null) {
            return false;
        }
        extns.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
        extns.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
        if (extns.isEmpty()) {
            return false;
        }
        return true;
    }

    private Set getExtensionOIDs(boolean critical) {
        if (getVersion() == 2) {
            X509Extensions extensions = this.f180c.getTBSCertList().getExtensions();
            if (extensions != null) {
                Set hashSet = new HashSet();
                Enumeration e = extensions.oids();
                while (e.hasMoreElements()) {
                    DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                    if (critical == extensions.getExtension(oid).isCritical()) {
                        hashSet.add(oid.getId());
                    }
                }
                return hashSet;
            }
        }
        return null;
    }

    public Set getCriticalExtensionOIDs() {
        return getExtensionOIDs(true);
    }

    public Set getNonCriticalExtensionOIDs() {
        return getExtensionOIDs(false);
    }

    public byte[] getExtensionValue(String oid) {
        X509Extensions exts = this.f180c.getTBSCertList().getExtensions();
        if (exts != null) {
            X509Extension ext = exts.getExtension(new DERObjectIdentifier(oid));
            if (ext != null) {
                try {
                    return ext.getValue().getEncoded();
                } catch (Exception e) {
                    throw new IllegalStateException("error parsing " + e.toString());
                }
            }
        }
        return null;
    }

    public byte[] getEncoded() throws CRLException {
        try {
            return this.f180c.getEncoded("DER");
        } catch (IOException e) {
            throw new CRLException(e.toString());
        }
    }

    public void verify(PublicKey key) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        verify(key, BouncyCastleProvider.PROVIDER_NAME);
    }

    public void verify(PublicKey key, String sigProvider) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        if (this.f180c.getSignatureAlgorithm().equals(this.f180c.getTBSCertList().getSignature())) {
            Signature sig = Signature.getInstance(getSigAlgName(), sigProvider);
            sig.initVerify(key);
            sig.update(getTBSCertList());
            if (!sig.verify(getSignature())) {
                throw new SignatureException("CRL does not verify with supplied public key.");
            }
            return;
        }
        throw new CRLException("Signature algorithm on CertificateList does not match TBSCertList.");
    }

    public int getVersion() {
        return this.f180c.getVersion();
    }

    public Principal getIssuerDN() {
        return new X509Principal(this.f180c.getIssuer());
    }

    public X500Principal getIssuerX500Principal() {
        try {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            new ASN1OutputStream(bOut).writeObject(this.f180c.getIssuer());
            return new X500Principal(bOut.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("can't encode issuer DN");
        }
    }

    public Date getThisUpdate() {
        return this.f180c.getThisUpdate().getDate();
    }

    public Date getNextUpdate() {
        if (this.f180c.getNextUpdate() != null) {
            return this.f180c.getNextUpdate().getDate();
        }
        return null;
    }

    private Set loadCRLEntries() {
        Set entrySet = new HashSet();
        Enumeration certs = this.f180c.getRevokedCertificateEnumeration();
        X500Principal previousCertificateIssuer = getIssuerX500Principal();
        while (certs.hasMoreElements()) {
            X509CRLEntryObject crlEntry = new X509CRLEntryObject((CRLEntry) certs.nextElement(), this.isIndirect, previousCertificateIssuer);
            entrySet.add(crlEntry);
            previousCertificateIssuer = crlEntry.getCertificateIssuer();
        }
        return entrySet;
    }

    public X509CRLEntry getRevokedCertificate(BigInteger serialNumber) {
        Enumeration certs = this.f180c.getRevokedCertificateEnumeration();
        X500Principal previousCertificateIssuer = getIssuerX500Principal();
        while (certs.hasMoreElements()) {
            CRLEntry entry = (CRLEntry) certs.nextElement();
            X509CRLEntryObject crlEntry = new X509CRLEntryObject(entry, this.isIndirect, previousCertificateIssuer);
            if (serialNumber.equals(entry.getUserCertificate().getValue())) {
                return crlEntry;
            }
            previousCertificateIssuer = crlEntry.getCertificateIssuer();
        }
        return null;
    }

    public Set getRevokedCertificates() {
        Set entrySet = loadCRLEntries();
        if (entrySet.isEmpty()) {
            return null;
        }
        return Collections.unmodifiableSet(entrySet);
    }

    public byte[] getTBSCertList() throws CRLException {
        try {
            return this.f180c.getTBSCertList().getEncoded("DER");
        } catch (IOException e) {
            throw new CRLException(e.toString());
        }
    }

    public byte[] getSignature() {
        return this.f180c.getSignature().getBytes();
    }

    public String getSigAlgName() {
        return this.sigAlgName;
    }

    public String getSigAlgOID() {
        return this.f180c.getSignatureAlgorithm().getObjectId().getId();
    }

    public byte[] getSigAlgParams() {
        if (this.sigAlgParams == null) {
            return null;
        }
        byte[] tmp = new byte[this.sigAlgParams.length];
        System.arraycopy(this.sigAlgParams, 0, tmp, 0, tmp.length);
        return tmp;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append("              Version: ").append(getVersion()).append(nl);
        buf.append("             IssuerDN: ").append(getIssuerDN()).append(nl);
        buf.append("          This update: ").append(getThisUpdate()).append(nl);
        buf.append("          Next update: ").append(getNextUpdate()).append(nl);
        buf.append("  Signature Algorithm: ").append(getSigAlgName()).append(nl);
        byte[] sig = getSignature();
        buf.append("            Signature: ").append(new String(Hex.encode(sig, 0, 20))).append(nl);
        for (int i = 20; i < sig.length; i += 20) {
            if (i < sig.length - 20) {
                buf.append("                       ").append(new String(Hex.encode(sig, i, 20))).append(nl);
            } else {
                buf.append("                       ").append(new String(Hex.encode(sig, i, sig.length - i))).append(nl);
            }
        }
        X509Extensions extensions = this.f180c.getTBSCertList().getExtensions();
        if (extensions != null) {
            Enumeration e = extensions.oids();
            if (e.hasMoreElements()) {
                buf.append("           Extensions: ").append(nl);
            }
            while (e.hasMoreElements()) {
                DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                X509Extension ext = extensions.getExtension(oid);
                if (ext.getValue() != null) {
                    ASN1InputStream dIn = new ASN1InputStream(ext.getValue().getOctets());
                    buf.append("                       critical(").append(ext.isCritical()).append(") ");
                    try {
                        if (oid.equals(X509Extensions.CRLNumber)) {
                            buf.append(new CRLNumber(DERInteger.getInstance(dIn.readObject()).getPositiveValue())).append(nl);
                        } else if (oid.equals(X509Extensions.DeltaCRLIndicator)) {
                            buf.append("Base CRL: " + new CRLNumber(DERInteger.getInstance(dIn.readObject()).getPositiveValue())).append(nl);
                        } else if (oid.equals(X509Extensions.IssuingDistributionPoint)) {
                            buf.append(new IssuingDistributionPoint((ASN1Sequence) dIn.readObject())).append(nl);
                        } else if (oid.equals(X509Extensions.CRLDistributionPoints)) {
                            buf.append(new CRLDistPoint((ASN1Sequence) dIn.readObject())).append(nl);
                        } else if (oid.equals(X509Extensions.FreshestCRL)) {
                            buf.append(new CRLDistPoint((ASN1Sequence) dIn.readObject())).append(nl);
                        } else {
                            buf.append(oid.getId());
                            buf.append(" value = ").append(ASN1Dump.dumpAsString(dIn.readObject())).append(nl);
                        }
                    } catch (Exception e2) {
                        buf.append(oid.getId());
                        buf.append(" value = ").append("*****").append(nl);
                    }
                } else {
                    buf.append(nl);
                }
            }
        }
        Set<Object> set = getRevokedCertificates();
        if (set != null) {
            for (Object append : set) {
                buf.append(append);
                buf.append(nl);
            }
        }
        return buf.toString();
    }

    public boolean isRevoked(Certificate cert) {
        if (cert.getType().equals("X.509")) {
            CRLEntry[] certs = this.f180c.getRevokedCertificates();
            if (certs != null) {
                BigInteger serial = ((X509Certificate) cert).getSerialNumber();
                for (CRLEntry userCertificate : certs) {
                    if (userCertificate.getUserCertificate().getValue().equals(serial)) {
                        return true;
                    }
                }
            }
            return false;
        }
        throw new RuntimeException("X.509 CRL used with non X.509 Cert");
    }

    private boolean isIndirectCRL() throws CRLException {
        byte[] idp = getExtensionValue(X509Extensions.IssuingDistributionPoint.getId());
        boolean isIndirect = false;
        if (idp != null) {
            try {
                isIndirect = IssuingDistributionPoint.getInstance(X509ExtensionUtil.fromExtensionValue(idp)).isIndirectCRL();
            } catch (Exception e) {
                throw new ExtCRLException("Exception reading IssuingDistributionPoint", e);
            }
        }
        return isIndirect;
    }
}
