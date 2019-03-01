package org.spongycastle.jce.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1OutputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.misc.MiscObjectIdentifiers;
import org.spongycastle.asn1.misc.NetscapeCertType;
import org.spongycastle.asn1.misc.NetscapeRevocationURL;
import org.spongycastle.asn1.misc.VerisignCzagExtension;
import org.spongycastle.asn1.util.ASN1Dump;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.BasicConstraints;
import org.spongycastle.asn1.x509.KeyUsage;
import org.spongycastle.asn1.x509.X509CertificateStructure;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.asn1.x509.X509Extensions;
import org.spongycastle.jce.X509Principal;
import org.spongycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;

public class X509CertificateObject extends X509Certificate implements PKCS12BagAttributeCarrier {
    private PKCS12BagAttributeCarrier attrCarrier = new PKCS12BagAttributeCarrierImpl();
    private BasicConstraints basicConstraints;
    /* renamed from: c */
    private X509CertificateStructure f424c;
    private int hashValue;
    private boolean hashValueSet;
    private boolean[] keyUsage;

    public X509CertificateObject(X509CertificateStructure c) throws CertificateParsingException {
        int i = 9;
        this.f424c = c;
        try {
            byte[] bytes = getExtensionBytes("2.5.29.19");
            if (bytes != null) {
                this.basicConstraints = BasicConstraints.getInstance(ASN1Object.fromByteArray(bytes));
            }
            try {
                bytes = getExtensionBytes("2.5.29.15");
                if (bytes != null) {
                    DERBitString bits = DERBitString.getInstance(ASN1Object.fromByteArray(bytes));
                    bytes = bits.getBytes();
                    int length = (bytes.length * 8) - bits.getPadBits();
                    if (length >= 9) {
                        i = length;
                    }
                    this.keyUsage = new boolean[i];
                    for (int i2 = 0; i2 != length; i2++) {
                        this.keyUsage[i2] = (bytes[i2 / 8] & (128 >>> (i2 % 8))) != 0;
                    }
                    return;
                }
                this.keyUsage = null;
            } catch (Exception e) {
                throw new CertificateParsingException("cannot construct KeyUsage: " + e);
            }
        } catch (Exception e2) {
            throw new CertificateParsingException("cannot construct BasicConstraints: " + e2);
        }
    }

    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        checkValidity(new Date());
    }

    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        if (date.getTime() > getNotAfter().getTime()) {
            throw new CertificateExpiredException("certificate expired on " + this.f424c.getEndDate().getTime());
        } else if (date.getTime() < getNotBefore().getTime()) {
            throw new CertificateNotYetValidException("certificate not valid till " + this.f424c.getStartDate().getTime());
        }
    }

    public int getVersion() {
        return this.f424c.getVersion();
    }

    public BigInteger getSerialNumber() {
        return this.f424c.getSerialNumber().getValue();
    }

    public Principal getIssuerDN() {
        return new X509Principal(this.f424c.getIssuer());
    }

    public X500Principal getIssuerX500Principal() {
        try {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            new ASN1OutputStream(bOut).writeObject(this.f424c.getIssuer());
            return new X500Principal(bOut.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("can't encode issuer DN");
        }
    }

    public Principal getSubjectDN() {
        return new X509Principal(this.f424c.getSubject());
    }

    public X500Principal getSubjectX500Principal() {
        try {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            new ASN1OutputStream(bOut).writeObject(this.f424c.getSubject());
            return new X500Principal(bOut.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("can't encode issuer DN");
        }
    }

    public Date getNotBefore() {
        return this.f424c.getStartDate().getDate();
    }

    public Date getNotAfter() {
        return this.f424c.getEndDate().getDate();
    }

    public byte[] getTBSCertificate() throws CertificateEncodingException {
        try {
            return this.f424c.getTBSCertificate().getEncoded("DER");
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public byte[] getSignature() {
        return this.f424c.getSignature().getBytes();
    }

    public String getSigAlgName() {
        String algName;
        Provider prov = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (prov != null) {
            algName = prov.getProperty("Alg.Alias.Signature." + getSigAlgOID());
            if (algName != null) {
                return algName;
            }
        }
        Provider[] provs = Security.getProviders();
        for (int i = 0; i != provs.length; i++) {
            algName = provs[i].getProperty("Alg.Alias.Signature." + getSigAlgOID());
            if (algName != null) {
                return algName;
            }
        }
        return getSigAlgOID();
    }

    public String getSigAlgOID() {
        return this.f424c.getSignatureAlgorithm().getObjectId().getId();
    }

    public byte[] getSigAlgParams() {
        if (this.f424c.getSignatureAlgorithm().getParameters() != null) {
            return this.f424c.getSignatureAlgorithm().getParameters().getDERObject().getDEREncoded();
        }
        return null;
    }

    public boolean[] getIssuerUniqueID() {
        DERBitString id = this.f424c.getTBSCertificate().getIssuerUniqueId();
        if (id == null) {
            return null;
        }
        byte[] bytes = id.getBytes();
        boolean[] zArr = new boolean[((bytes.length * 8) - id.getPadBits())];
        for (int i = 0; i != zArr.length; i++) {
            zArr[i] = (bytes[i / 8] & (128 >>> (i % 8))) != 0;
        }
        return zArr;
    }

    public boolean[] getSubjectUniqueID() {
        DERBitString id = this.f424c.getTBSCertificate().getSubjectUniqueId();
        if (id == null) {
            return null;
        }
        byte[] bytes = id.getBytes();
        boolean[] zArr = new boolean[((bytes.length * 8) - id.getPadBits())];
        for (int i = 0; i != zArr.length; i++) {
            zArr[i] = (bytes[i / 8] & (128 >>> (i % 8))) != 0;
        }
        return zArr;
    }

    public boolean[] getKeyUsage() {
        return this.keyUsage;
    }

    public List getExtendedKeyUsage() throws CertificateParsingException {
        byte[] bytes = getExtensionBytes("2.5.29.37");
        if (bytes == null) {
            return null;
        }
        try {
            ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(bytes).readObject();
            List list = new ArrayList();
            for (int i = 0; i != seq.size(); i++) {
                list.add(((DERObjectIdentifier) seq.getObjectAt(i)).getId());
            }
            return Collections.unmodifiableList(list);
        } catch (Exception e) {
            throw new CertificateParsingException("error processing extended key usage extension");
        }
    }

    public int getBasicConstraints() {
        if (this.basicConstraints == null || !this.basicConstraints.isCA()) {
            return -1;
        }
        if (this.basicConstraints.getPathLenConstraint() == null) {
            return Integer.MAX_VALUE;
        }
        return this.basicConstraints.getPathLenConstraint().intValue();
    }

    public Set getCriticalExtensionOIDs() {
        if (getVersion() == 3) {
            Set hashSet = new HashSet();
            X509Extensions extensions = this.f424c.getTBSCertificate().getExtensions();
            if (extensions != null) {
                Enumeration e = extensions.oids();
                while (e.hasMoreElements()) {
                    DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                    if (extensions.getExtension(oid).isCritical()) {
                        hashSet.add(oid.getId());
                    }
                }
                return hashSet;
            }
        }
        return null;
    }

    private byte[] getExtensionBytes(String oid) {
        X509Extensions exts = this.f424c.getTBSCertificate().getExtensions();
        if (exts != null) {
            X509Extension ext = exts.getExtension(new DERObjectIdentifier(oid));
            if (ext != null) {
                return ext.getValue().getOctets();
            }
        }
        return null;
    }

    public byte[] getExtensionValue(String oid) {
        X509Extensions exts = this.f424c.getTBSCertificate().getExtensions();
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

    public Set getNonCriticalExtensionOIDs() {
        if (getVersion() == 3) {
            Set hashSet = new HashSet();
            X509Extensions extensions = this.f424c.getTBSCertificate().getExtensions();
            if (extensions != null) {
                Enumeration e = extensions.oids();
                while (e.hasMoreElements()) {
                    DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                    if (!extensions.getExtension(oid).isCritical()) {
                        hashSet.add(oid.getId());
                    }
                }
                return hashSet;
            }
        }
        return null;
    }

    public boolean hasUnsupportedCriticalExtension() {
        if (getVersion() == 3) {
            X509Extensions extensions = this.f424c.getTBSCertificate().getExtensions();
            if (extensions != null) {
                Enumeration e = extensions.oids();
                while (e.hasMoreElements()) {
                    DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                    String oidId = oid.getId();
                    if (!oidId.equals(RFC3280CertPathUtilities.KEY_USAGE) && !oidId.equals(RFC3280CertPathUtilities.CERTIFICATE_POLICIES) && !oidId.equals(RFC3280CertPathUtilities.POLICY_MAPPINGS) && !oidId.equals(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY) && !oidId.equals(RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS) && !oidId.equals(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT) && !oidId.equals(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR) && !oidId.equals(RFC3280CertPathUtilities.POLICY_CONSTRAINTS) && !oidId.equals(RFC3280CertPathUtilities.BASIC_CONSTRAINTS) && !oidId.equals(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME) && !oidId.equals(RFC3280CertPathUtilities.NAME_CONSTRAINTS) && extensions.getExtension(oid).isCritical()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public PublicKey getPublicKey() {
        return JDKKeyFactory.createPublicKeyFromPublicKeyInfo(this.f424c.getSubjectPublicKeyInfo());
    }

    public byte[] getEncoded() throws CertificateEncodingException {
        try {
            return this.f424c.getEncoded("DER");
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public boolean equals(Object o) {
        boolean z = false;
        if (o == this) {
            return true;
        }
        if (!(o instanceof Certificate)) {
            return z;
        }
        try {
            return Arrays.areEqual(getEncoded(), ((Certificate) o).getEncoded());
        } catch (CertificateEncodingException e) {
            return z;
        }
    }

    public synchronized int hashCode() {
        if (!this.hashValueSet) {
            this.hashValue = calculateHashCode();
            this.hashValueSet = true;
        }
        return this.hashValue;
    }

    private int calculateHashCode() {
        int hashCode = 0;
        try {
            byte[] certData = getEncoded();
            for (int i = 1; i < certData.length; i++) {
                hashCode += certData[i] * i;
            }
            return hashCode;
        } catch (CertificateEncodingException e) {
            return 0;
        }
    }

    public void setBagAttribute(DERObjectIdentifier oid, DEREncodable attribute) {
        this.attrCarrier.setBagAttribute(oid, attribute);
    }

    public DEREncodable getBagAttribute(DERObjectIdentifier oid) {
        return this.attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys() {
        return this.attrCarrier.getBagAttributeKeys();
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append("  [0]         Version: ").append(getVersion()).append(nl);
        buf.append("         SerialNumber: ").append(getSerialNumber()).append(nl);
        buf.append("             IssuerDN: ").append(getIssuerDN()).append(nl);
        buf.append("           Start Date: ").append(getNotBefore()).append(nl);
        buf.append("           Final Date: ").append(getNotAfter()).append(nl);
        buf.append("            SubjectDN: ").append(getSubjectDN()).append(nl);
        buf.append("           Public Key: ").append(getPublicKey()).append(nl);
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
        X509Extensions extensions = this.f424c.getTBSCertificate().getExtensions();
        if (extensions != null) {
            Enumeration e = extensions.oids();
            if (e.hasMoreElements()) {
                buf.append("       Extensions: \n");
            }
            while (e.hasMoreElements()) {
                DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                X509Extension ext = extensions.getExtension(oid);
                if (ext.getValue() != null) {
                    ASN1InputStream dIn = new ASN1InputStream(ext.getValue().getOctets());
                    buf.append("                       critical(").append(ext.isCritical()).append(") ");
                    try {
                        if (oid.equals(X509Extensions.BasicConstraints)) {
                            buf.append(new BasicConstraints((ASN1Sequence) dIn.readObject())).append(nl);
                        } else if (oid.equals(X509Extensions.KeyUsage)) {
                            buf.append(new KeyUsage((DERBitString) dIn.readObject())).append(nl);
                        } else if (oid.equals(MiscObjectIdentifiers.netscapeCertType)) {
                            buf.append(new NetscapeCertType((DERBitString) dIn.readObject())).append(nl);
                        } else if (oid.equals(MiscObjectIdentifiers.netscapeRevocationURL)) {
                            buf.append(new NetscapeRevocationURL((DERIA5String) dIn.readObject())).append(nl);
                        } else if (oid.equals(MiscObjectIdentifiers.verisignCzagExtension)) {
                            buf.append(new VerisignCzagExtension((DERIA5String) dIn.readObject())).append(nl);
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
        return buf.toString();
    }

    public final void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        Signature signature;
        String sigName = X509SignatureUtil.getSignatureName(this.f424c.getSignatureAlgorithm());
        try {
            signature = Signature.getInstance(sigName, BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception e) {
            signature = Signature.getInstance(sigName);
        }
        checkSignature(key, signature);
    }

    public final void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        checkSignature(key, Signature.getInstance(X509SignatureUtil.getSignatureName(this.f424c.getSignatureAlgorithm()), sigProvider));
    }

    private void checkSignature(PublicKey key, Signature signature) throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if (isAlgIdEqual(this.f424c.getSignatureAlgorithm(), this.f424c.getTBSCertificate().getSignature())) {
            X509SignatureUtil.setSignatureParameters(signature, this.f424c.getSignatureAlgorithm().getParameters());
            signature.initVerify(key);
            signature.update(getTBSCertificate());
            if (!signature.verify(getSignature())) {
                throw new InvalidKeyException("Public key presented not for certificate signature");
            }
            return;
        }
        throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
    }

    private boolean isAlgIdEqual(AlgorithmIdentifier id1, AlgorithmIdentifier id2) {
        if (!id1.getObjectId().equals(id2.getObjectId())) {
            return false;
        }
        if (id1.getParameters() == null) {
            if (id2.getParameters() == null || id2.getParameters().equals(DERNull.INSTANCE)) {
                return true;
            }
            return false;
        } else if (id2.getParameters() != null) {
            return id1.getParameters().equals(id2.getParameters());
        } else {
            if (id1.getParameters() == null || id1.getParameters().equals(DERNull.INSTANCE)) {
                return true;
            }
            return false;
        }
    }
}
