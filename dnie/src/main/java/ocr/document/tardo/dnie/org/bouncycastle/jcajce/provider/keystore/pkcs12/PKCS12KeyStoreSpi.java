package org.bouncycastle.jcajce.provider.keystore.pkcs12;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BEROutputStream;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.PKCS12StoreParameter;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jcajce.provider.util.SecretKeyUtil;
import org.bouncycastle.jce.interfaces.BCKeyStore;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKPKCS12StoreParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PKCS12KeyStoreSpi extends KeyStoreSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers, BCKeyStore {
    static final int CERTIFICATE = 1;
    static final int KEY = 2;
    static final int KEY_PRIVATE = 0;
    static final int KEY_PUBLIC = 1;
    static final int KEY_SECRET = 2;
    private static final int MIN_ITERATIONS = 1024;
    static final int NULL = 0;
    private static final int SALT_SIZE = 20;
    static final int SEALED = 4;
    static final int SECRET = 3;
    private static final Provider bcProvider = new BouncyCastleProvider();
    private ASN1ObjectIdentifier certAlgorithm;
    private CertificateFactory certFact;
    private IgnoresCaseHashtable certs = new IgnoresCaseHashtable();
    private Hashtable chainCerts = new Hashtable();
    private ASN1ObjectIdentifier keyAlgorithm;
    private Hashtable keyCerts = new Hashtable();
    private IgnoresCaseHashtable keys = new IgnoresCaseHashtable();
    private Hashtable localIds = new Hashtable();
    protected SecureRandom random = new SecureRandom();

    private class CertId {
        byte[] id;

        CertId(PublicKey publicKey) {
            this.id = PKCS12KeyStoreSpi.this.createSubjectKeyId(publicKey).getKeyIdentifier();
        }

        CertId(byte[] bArr) {
            this.id = bArr;
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof CertId)) {
                return false;
            }
            return Arrays.areEqual(this.id, ((CertId) obj).id);
        }

        public int hashCode() {
            return Arrays.hashCode(this.id);
        }
    }

    private static class IgnoresCaseHashtable {
        private Hashtable keys;
        private Hashtable orig;

        private IgnoresCaseHashtable() {
            this.orig = new Hashtable();
            this.keys = new Hashtable();
        }

        public Enumeration elements() {
            return this.orig.elements();
        }

        public Object get(String str) {
            String str2 = (String) this.keys.get(str == null ? null : Strings.toLowerCase(str));
            return str2 == null ? null : this.orig.get(str2);
        }

        public Enumeration keys() {
            return this.orig.keys();
        }

        public void put(String str, Object obj) {
            Object obj2;
            if (str == null) {
                obj2 = null;
            } else {
                String toLowerCase = Strings.toLowerCase(str);
            }
            String str2 = (String) this.keys.get(obj2);
            if (str2 != null) {
                this.orig.remove(str2);
            }
            this.keys.put(obj2, str);
            this.orig.put(str, obj);
        }

        public Object remove(String str) {
            String str2 = (String) this.keys.remove(str == null ? null : Strings.toLowerCase(str));
            return str2 == null ? null : this.orig.remove(str2);
        }
    }

    public static class BCPKCS12KeyStore3DES extends PKCS12KeyStoreSpi {
        public BCPKCS12KeyStore3DES() {
            super(PKCS12KeyStoreSpi.bcProvider, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC);
        }
    }

    public static class BCPKCS12KeyStore extends PKCS12KeyStoreSpi {
        public BCPKCS12KeyStore() {
            super(PKCS12KeyStoreSpi.bcProvider, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd40BitRC2_CBC);
        }
    }

    public static class DefPKCS12KeyStore3DES extends PKCS12KeyStoreSpi {
        public DefPKCS12KeyStore3DES() {
            super(null, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC);
        }
    }

    public static class DefPKCS12KeyStore extends PKCS12KeyStoreSpi {
        public DefPKCS12KeyStore() {
            super(null, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd40BitRC2_CBC);
        }
    }

    public PKCS12KeyStoreSpi(Provider provider, ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1ObjectIdentifier aSN1ObjectIdentifier2) {
        this.keyAlgorithm = aSN1ObjectIdentifier;
        this.certAlgorithm = aSN1ObjectIdentifier2;
        if (provider != null) {
            try {
                this.certFact = CertificateFactory.getInstance("X.509", provider);
                return;
            } catch (Exception e) {
                throw new IllegalArgumentException("can't create cert factory - " + e.toString());
            }
        }
        this.certFact = CertificateFactory.getInstance("X.509");
    }

    private static byte[] calculatePbeMac(ASN1ObjectIdentifier aSN1ObjectIdentifier, byte[] bArr, int i, char[] cArr, boolean z, byte[] bArr2) throws Exception {
        SecretKeyFactory instance = SecretKeyFactory.getInstance(aSN1ObjectIdentifier.getId(), bcProvider);
        AlgorithmParameterSpec pBEParameterSpec = new PBEParameterSpec(bArr, i);
        BCPBEKey bCPBEKey = (BCPBEKey) instance.generateSecret(new PBEKeySpec(cArr));
        bCPBEKey.setTryWrongPKCS12Zero(z);
        Mac instance2 = Mac.getInstance(aSN1ObjectIdentifier.getId(), bcProvider);
        instance2.init(bCPBEKey, pBEParameterSpec);
        instance2.update(bArr2);
        return instance2.doFinal();
    }

    private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey) {
        try {
            return new SubjectKeyIdentifier(new SubjectPublicKeyInfo((ASN1Sequence) ASN1Primitive.fromByteArray(publicKey.getEncoded())));
        } catch (Exception e) {
            throw new RuntimeException("error creating key");
        }
    }

    private void doStore(OutputStream outputStream, char[] cArr, boolean z) throws IOException {
        if (cArr == null) {
            throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
        }
        Enumeration bagAttributeKeys;
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        Enumeration keys = this.keys.keys();
        while (keys.hasMoreElements()) {
            PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier;
            Object obj;
            byte[] bArr = new byte[20];
            this.random.nextBytes(bArr);
            String str = (String) keys.nextElement();
            PrivateKey privateKey = (PrivateKey) this.keys.get(str);
            PKCS12PBEParams pKCS12PBEParams = new PKCS12PBEParams(bArr, 1024);
            EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(this.keyAlgorithm, pKCS12PBEParams.toASN1Primitive()), wrapKey(this.keyAlgorithm.getId(), privateKey, pKCS12PBEParams, cArr));
            ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
            if (privateKey instanceof PKCS12BagAttributeCarrier) {
                pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier) privateKey;
                DERBMPString dERBMPString = (DERBMPString) pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_friendlyName);
                if (dERBMPString == null || !dERBMPString.getString().equals(str)) {
                    pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(str));
                }
                if (pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_localKeyId) == null) {
                    pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_localKeyId, createSubjectKeyId(engineGetCertificate(str).getPublicKey()));
                }
                Enumeration bagAttributeKeys2 = pKCS12BagAttributeCarrier.getBagAttributeKeys();
                obj = null;
                while (bagAttributeKeys2.hasMoreElements()) {
                    ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) bagAttributeKeys2.nextElement();
                    ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector();
                    aSN1EncodableVector3.add(aSN1ObjectIdentifier);
                    aSN1EncodableVector3.add(new DERSet(pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier)));
                    obj = 1;
                    aSN1EncodableVector2.add(new DERSequence(aSN1EncodableVector3));
                }
            } else {
                obj = null;
            }
            if (obj == null) {
                ASN1EncodableVector aSN1EncodableVector4 = new ASN1EncodableVector();
                Certificate engineGetCertificate = engineGetCertificate(str);
                aSN1EncodableVector4.add(pkcs_9_at_localKeyId);
                aSN1EncodableVector4.add(new DERSet(createSubjectKeyId(engineGetCertificate.getPublicKey())));
                aSN1EncodableVector2.add(new DERSequence(aSN1EncodableVector4));
                aSN1EncodableVector4 = new ASN1EncodableVector();
                aSN1EncodableVector4.add(pkcs_9_at_friendlyName);
                aSN1EncodableVector4.add(new DERSet(new DERBMPString(str)));
                aSN1EncodableVector2.add(new DERSequence(aSN1EncodableVector4));
            }
            aSN1EncodableVector.add(new SafeBag(pkcs8ShroudedKeyBag, encryptedPrivateKeyInfo.toASN1Primitive(), new DERSet(aSN1EncodableVector2)));
        }
        ASN1Encodable bEROctetString = new BEROctetString(new DERSequence(aSN1EncodableVector).getEncoded("DER"));
        byte[] bArr2 = new byte[20];
        this.random.nextBytes(bArr2);
        ASN1EncodableVector aSN1EncodableVector5 = new ASN1EncodableVector();
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(this.certAlgorithm, new PKCS12PBEParams(bArr2, 1024).toASN1Primitive());
        Hashtable hashtable = new Hashtable();
        Enumeration keys2 = this.keys.keys();
        while (keys2.hasMoreElements()) {
            ASN1EncodableVector aSN1EncodableVector6;
            DERBMPString dERBMPString2;
            try {
                Object obj2;
                str = (String) keys2.nextElement();
                Certificate engineGetCertificate2 = engineGetCertificate(str);
                CertBag certBag = new CertBag(x509Certificate, new DEROctetString(engineGetCertificate2.getEncoded()));
                aSN1EncodableVector6 = new ASN1EncodableVector();
                if (engineGetCertificate2 instanceof PKCS12BagAttributeCarrier) {
                    pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier) engineGetCertificate2;
                    dERBMPString2 = (DERBMPString) pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_friendlyName);
                    if (dERBMPString2 == null || !dERBMPString2.getString().equals(str)) {
                        pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(str));
                    }
                    if (pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_localKeyId) == null) {
                        pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_localKeyId, createSubjectKeyId(engineGetCertificate2.getPublicKey()));
                    }
                    bagAttributeKeys = pKCS12BagAttributeCarrier.getBagAttributeKeys();
                    Object obj3 = null;
                    while (bagAttributeKeys.hasMoreElements()) {
                        ASN1ObjectIdentifier aSN1ObjectIdentifier2 = (ASN1ObjectIdentifier) bagAttributeKeys.nextElement();
                        ASN1EncodableVector aSN1EncodableVector7 = new ASN1EncodableVector();
                        aSN1EncodableVector7.add(aSN1ObjectIdentifier2);
                        aSN1EncodableVector7.add(new DERSet(pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier2)));
                        aSN1EncodableVector6.add(new DERSequence(aSN1EncodableVector7));
                        obj3 = 1;
                    }
                    obj2 = obj3;
                } else {
                    obj2 = null;
                }
                if (obj2 == null) {
                    aSN1EncodableVector4 = new ASN1EncodableVector();
                    aSN1EncodableVector4.add(pkcs_9_at_localKeyId);
                    aSN1EncodableVector4.add(new DERSet(createSubjectKeyId(engineGetCertificate2.getPublicKey())));
                    aSN1EncodableVector6.add(new DERSequence(aSN1EncodableVector4));
                    aSN1EncodableVector4 = new ASN1EncodableVector();
                    aSN1EncodableVector4.add(pkcs_9_at_friendlyName);
                    aSN1EncodableVector4.add(new DERSet(new DERBMPString(str)));
                    aSN1EncodableVector6.add(new DERSequence(aSN1EncodableVector4));
                }
                aSN1EncodableVector5.add(new SafeBag(certBag, certBag.toASN1Primitive(), new DERSet(aSN1EncodableVector6)));
                hashtable.put(engineGetCertificate2, engineGetCertificate2);
            } catch (CertificateEncodingException e) {
                throw new IOException("Error encoding certificate: " + e.toString());
            }
        }
        keys2 = this.certs.keys();
        while (keys2.hasMoreElements()) {
            try {
                str = (String) keys2.nextElement();
                Certificate certificate = (Certificate) this.certs.get(str);
                Object obj4 = null;
                if (this.keys.get(str) == null) {
                    certBag = new CertBag(x509Certificate, new DEROctetString(certificate.getEncoded()));
                    aSN1EncodableVector6 = new ASN1EncodableVector();
                    if (certificate instanceof PKCS12BagAttributeCarrier) {
                        PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier2 = (PKCS12BagAttributeCarrier) certificate;
                        dERBMPString2 = (DERBMPString) pKCS12BagAttributeCarrier2.getBagAttribute(pkcs_9_at_friendlyName);
                        if (dERBMPString2 == null || !dERBMPString2.getString().equals(str)) {
                            pKCS12BagAttributeCarrier2.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(str));
                        }
                        bagAttributeKeys = pKCS12BagAttributeCarrier2.getBagAttributeKeys();
                        while (bagAttributeKeys.hasMoreElements()) {
                            aSN1ObjectIdentifier2 = (ASN1ObjectIdentifier) bagAttributeKeys.nextElement();
                            if (!aSN1ObjectIdentifier2.equals(PKCSObjectIdentifiers.pkcs_9_at_localKeyId)) {
                                aSN1EncodableVector7 = new ASN1EncodableVector();
                                aSN1EncodableVector7.add(aSN1ObjectIdentifier2);
                                aSN1EncodableVector7.add(new DERSet(pKCS12BagAttributeCarrier2.getBagAttribute(aSN1ObjectIdentifier2)));
                                aSN1EncodableVector6.add(new DERSequence(aSN1EncodableVector7));
                                obj4 = 1;
                            }
                        }
                    }
                    if (obj4 == null) {
                        aSN1EncodableVector3 = new ASN1EncodableVector();
                        aSN1EncodableVector3.add(pkcs_9_at_friendlyName);
                        aSN1EncodableVector3.add(new DERSet(new DERBMPString(str)));
                        aSN1EncodableVector6.add(new DERSequence(aSN1EncodableVector3));
                    }
                    aSN1EncodableVector5.add(new SafeBag(certBag, certBag.toASN1Primitive(), new DERSet(aSN1EncodableVector6)));
                    hashtable.put(certificate, certificate);
                }
            } catch (CertificateEncodingException e2) {
                throw new IOException("Error encoding certificate: " + e2.toString());
            }
        }
        Enumeration keys3 = this.chainCerts.keys();
        while (keys3.hasMoreElements()) {
            try {
                Certificate certificate2 = (Certificate) this.chainCerts.get((CertId) keys3.nextElement());
                if (hashtable.get(certificate2) == null) {
                    CertBag certBag2 = new CertBag(x509Certificate, new DEROctetString(certificate2.getEncoded()));
                    aSN1EncodableVector7 = new ASN1EncodableVector();
                    if (certificate2 instanceof PKCS12BagAttributeCarrier) {
                        PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier3 = (PKCS12BagAttributeCarrier) certificate2;
                        keys2 = pKCS12BagAttributeCarrier3.getBagAttributeKeys();
                        while (keys2.hasMoreElements()) {
                            ASN1ObjectIdentifier aSN1ObjectIdentifier3 = (ASN1ObjectIdentifier) keys2.nextElement();
                            if (!aSN1ObjectIdentifier3.equals(PKCSObjectIdentifiers.pkcs_9_at_localKeyId)) {
                                ASN1EncodableVector aSN1EncodableVector8 = new ASN1EncodableVector();
                                aSN1EncodableVector8.add(aSN1ObjectIdentifier3);
                                aSN1EncodableVector8.add(new DERSet(pKCS12BagAttributeCarrier3.getBagAttribute(aSN1ObjectIdentifier3)));
                                aSN1EncodableVector7.add(new DERSequence(aSN1EncodableVector8));
                            }
                        }
                    }
                    aSN1EncodableVector5.add(new SafeBag(certBag, certBag2.toASN1Primitive(), new DERSet(aSN1EncodableVector7)));
                }
            } catch (CertificateEncodingException e22) {
                throw new IOException("Error encoding certificate: " + e22.toString());
            }
        }
        EncryptedData encryptedData = new EncryptedData(data, algorithmIdentifier, new BEROctetString(cryptData(true, algorithmIdentifier, cArr, false, new DERSequence(aSN1EncodableVector5).getEncoded("DER"))));
        ASN1Encodable authenticatedSafe = new AuthenticatedSafe(new ContentInfo[]{new ContentInfo(data, bEROctetString), new ContentInfo(encryptedData, encryptedData.toASN1Primitive())});
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        (z ? new DEROutputStream(byteArrayOutputStream) : new BEROutputStream(byteArrayOutputStream)).writeObject(authenticatedSafe);
        ContentInfo contentInfo = new ContentInfo(data, new BEROctetString(byteArrayOutputStream.toByteArray()));
        byte[] bArr3 = new byte[20];
        this.random.nextBytes(bArr3);
        try {
            (z ? new DEROutputStream(outputStream) : new BEROutputStream(outputStream)).writeObject(new Pfx(contentInfo, new MacData(new DigestInfo(new AlgorithmIdentifier(id_SHA1, DERNull.INSTANCE), calculatePbeMac(id_SHA1, bArr3, 1024, cArr, false, ((ASN1OctetString) contentInfo.getContent()).getOctets())), bArr3, 1024)));
        } catch (Exception e3) {
            throw new IOException("error constructing MAC: " + e3.toString());
        }
    }

    protected byte[] cryptData(boolean z, AlgorithmIdentifier algorithmIdentifier, char[] cArr, boolean z2, byte[] bArr) throws IOException {
        String id = algorithmIdentifier.getAlgorithm().getId();
        PKCS12PBEParams instance = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());
        KeySpec pBEKeySpec = new PBEKeySpec(cArr);
        try {
            SecretKeyFactory instance2 = SecretKeyFactory.getInstance(id, bcProvider);
            AlgorithmParameterSpec pBEParameterSpec = new PBEParameterSpec(instance.getIV(), instance.getIterations().intValue());
            BCPBEKey bCPBEKey = (BCPBEKey) instance2.generateSecret(pBEKeySpec);
            bCPBEKey.setTryWrongPKCS12Zero(z2);
            Cipher instance3 = Cipher.getInstance(id, bcProvider);
            instance3.init(z ? 1 : 2, bCPBEKey, pBEParameterSpec);
            return instance3.doFinal(bArr);
        } catch (Exception e) {
            throw new IOException("exception decrypting data - " + e.toString());
        }
    }

    public Enumeration engineAliases() {
        Hashtable hashtable = new Hashtable();
        Enumeration keys = this.certs.keys();
        while (keys.hasMoreElements()) {
            hashtable.put(keys.nextElement(), "cert");
        }
        Enumeration keys2 = this.keys.keys();
        while (keys2.hasMoreElements()) {
            String str = (String) keys2.nextElement();
            if (hashtable.get(str) == null) {
                hashtable.put(str, "key");
            }
        }
        return hashtable.keys();
    }

    public boolean engineContainsAlias(String str) {
        return (this.certs.get(str) == null && this.keys.get(str) == null) ? false : true;
    }

    public void engineDeleteEntry(String str) throws KeyStoreException {
        Key key = (Key) this.keys.remove(str);
        Certificate certificate = (Certificate) this.certs.remove(str);
        if (certificate != null) {
            this.chainCerts.remove(new CertId(certificate.getPublicKey()));
        }
        if (key != null) {
            String str2 = (String) this.localIds.remove(str);
            Certificate certificate2 = str2 != null ? (Certificate) this.keyCerts.remove(str2) : certificate;
            if (certificate2 != null) {
                this.chainCerts.remove(new CertId(certificate2.getPublicKey()));
            }
        }
    }

    public Certificate engineGetCertificate(String str) {
        if (str == null) {
            throw new IllegalArgumentException("null alias passed to getCertificate.");
        }
        Certificate certificate = (Certificate) this.certs.get(str);
        if (certificate != null) {
            return certificate;
        }
        String str2 = (String) this.localIds.get(str);
        return str2 != null ? (Certificate) this.keyCerts.get(str2) : (Certificate) this.keyCerts.get(str);
    }

    public String engineGetCertificateAlias(Certificate certificate) {
        Enumeration elements = this.certs.elements();
        Enumeration keys = this.certs.keys();
        while (elements.hasMoreElements()) {
            String str = (String) keys.nextElement();
            if (((Certificate) elements.nextElement()).equals(certificate)) {
                return str;
            }
        }
        elements = this.keyCerts.elements();
        keys = this.keyCerts.keys();
        while (elements.hasMoreElements()) {
            str = (String) keys.nextElement();
            if (((Certificate) elements.nextElement()).equals(certificate)) {
                return str;
            }
        }
        return null;
    }

    public Certificate[] engineGetCertificateChain(String str) {
        Certificate[] certificateArr = null;
        if (str == null) {
            throw new IllegalArgumentException("null alias passed to getCertificateChain.");
        }
        if (engineIsKeyEntry(str)) {
            X509Certificate engineGetCertificate = engineGetCertificate(str);
            if (engineGetCertificate != null) {
                Vector vector = new Vector();
                while (engineGetCertificate != null) {
                    Certificate certificate;
                    X509Certificate x509Certificate = engineGetCertificate;
                    byte[] extensionValue = x509Certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
                    if (extensionValue != null) {
                        try {
                            AuthorityKeyIdentifier instance = AuthorityKeyIdentifier.getInstance(new ASN1InputStream(((ASN1OctetString) new ASN1InputStream(extensionValue).readObject()).getOctets()).readObject());
                            certificate = instance.getKeyIdentifier() != null ? (Certificate) this.chainCerts.get(new CertId(instance.getKeyIdentifier())) : null;
                        } catch (IOException e) {
                            throw new RuntimeException(e.toString());
                        }
                    }
                    certificate = null;
                    if (certificate == null) {
                        Principal issuerDN = x509Certificate.getIssuerDN();
                        if (!issuerDN.equals(x509Certificate.getSubjectDN())) {
                            Enumeration keys = this.chainCerts.keys();
                            while (keys.hasMoreElements()) {
                                X509Certificate x509Certificate2 = (X509Certificate) this.chainCerts.get(keys.nextElement());
                                if (x509Certificate2.getSubjectDN().equals(issuerDN)) {
                                    try {
                                        x509Certificate.verify(x509Certificate2.getPublicKey());
                                        x509Certificate = x509Certificate2;
                                        break;
                                    } catch (Exception e2) {
                                    }
                                }
                            }
                        }
                    }
                    Certificate certificate2 = certificate;
                    vector.addElement(engineGetCertificate);
                    if (x509Certificate == engineGetCertificate) {
                        x509Certificate = null;
                    }
                    engineGetCertificate = x509Certificate;
                }
                certificateArr = new Certificate[vector.size()];
                for (int i = 0; i != certificateArr.length; i++) {
                    certificateArr[i] = (Certificate) vector.elementAt(i);
                }
            }
        }
        return certificateArr;
    }

    public Date engineGetCreationDate(String str) {
        if (str != null) {
            return (this.keys.get(str) == null && this.certs.get(str) == null) ? null : new Date();
        } else {
            throw new NullPointerException("alias == null");
        }
    }

    public Key engineGetKey(String str, char[] cArr) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        if (str != null) {
            return (Key) this.keys.get(str);
        }
        throw new IllegalArgumentException("null alias passed to getKey.");
    }

    public boolean engineIsCertificateEntry(String str) {
        return this.certs.get(str) != null && this.keys.get(str) == null;
    }

    public boolean engineIsKeyEntry(String str) {
        return this.keys.get(str) != null;
    }

    public void engineLoad(InputStream inputStream, char[] cArr) throws IOException {
        if (inputStream != null) {
            if (cArr == null) {
                throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
            }
            InputStream bufferedInputStream = new BufferedInputStream(inputStream);
            bufferedInputStream.mark(10);
            if (bufferedInputStream.read() != 48) {
                throw new IOException("stream does not represent a PKCS12 key store");
            }
            boolean z;
            ASN1Sequence aSN1Sequence;
            String str;
            bufferedInputStream.reset();
            Pfx instance = Pfx.getInstance((ASN1Sequence) new ASN1InputStream(bufferedInputStream).readObject());
            ContentInfo authSafe = instance.getAuthSafe();
            Vector vector = new Vector();
            Object obj = null;
            if (instance.getMacData() != null) {
                MacData macData = instance.getMacData();
                DigestInfo mac = macData.getMac();
                AlgorithmIdentifier algorithmId = mac.getAlgorithmId();
                byte[] salt = macData.getSalt();
                int intValue = macData.getIterationCount().intValue();
                byte[] octets = ((ASN1OctetString) authSafe.getContent()).getOctets();
                try {
                    boolean z2;
                    byte[] calculatePbeMac = calculatePbeMac(algorithmId.getAlgorithm(), salt, intValue, cArr, false, octets);
                    byte[] digest = mac.getDigest();
                    if (Arrays.constantTimeAreEqual(calculatePbeMac, digest)) {
                        z2 = false;
                    } else if (cArr.length > 0) {
                        throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                    } else if (Arrays.constantTimeAreEqual(calculatePbeMac(algorithmId.getAlgorithm(), salt, intValue, cArr, true, octets), digest)) {
                        z2 = true;
                    } else {
                        throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                    }
                    z = z2;
                } catch (IOException e) {
                    throw e;
                } catch (Exception e2) {
                    throw new IOException("error constructing MAC: " + e2.toString());
                }
            }
            z = false;
            this.keys = new IgnoresCaseHashtable();
            this.localIds = new Hashtable();
            if (authSafe.getContentType().equals(data)) {
                ContentInfo[] contentInfo = AuthenticatedSafe.getInstance(new ASN1InputStream(((ASN1OctetString) authSafe.getContent()).getOctets()).readObject()).getContentInfo();
                int i = 0;
                while (i != contentInfo.length) {
                    Object obj2;
                    SafeBag instance2;
                    EncryptedPrivateKeyInfo instance3;
                    PrivateKey unwrapKey;
                    PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier;
                    ASN1OctetString aSN1OctetString;
                    Enumeration objects;
                    ASN1Sequence aSN1Sequence2;
                    ASN1ObjectIdentifier aSN1ObjectIdentifier;
                    ASN1Set aSN1Set;
                    ASN1Encodable aSN1Encodable;
                    ASN1Encodable bagAttribute;
                    String string;
                    ASN1OctetString aSN1OctetString2;
                    String str2;
                    String str3;
                    if (contentInfo[i].getContentType().equals(data)) {
                        aSN1Sequence = (ASN1Sequence) new ASN1InputStream(((ASN1OctetString) contentInfo[i].getContent()).getOctets()).readObject();
                        Object obj3 = obj;
                        int i2 = 0;
                        while (i2 != aSN1Sequence.size()) {
                            Object obj4;
                            instance2 = SafeBag.getInstance(aSN1Sequence.getObjectAt(i2));
                            if (instance2.getBagId().equals(pkcs8ShroudedKeyBag)) {
                                instance3 = EncryptedPrivateKeyInfo.getInstance(instance2.getBagValue());
                                unwrapKey = unwrapKey(instance3.getEncryptionAlgorithm(), instance3.getEncryptedData(), cArr, z);
                                pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier) unwrapKey;
                                Object obj5 = null;
                                aSN1OctetString = null;
                                if (instance2.getBagAttributes() != null) {
                                    objects = instance2.getBagAttributes().getObjects();
                                    while (objects.hasMoreElements()) {
                                        aSN1Sequence2 = (ASN1Sequence) objects.nextElement();
                                        aSN1ObjectIdentifier = (ASN1ObjectIdentifier) aSN1Sequence2.getObjectAt(0);
                                        aSN1Set = (ASN1Set) aSN1Sequence2.getObjectAt(1);
                                        if (aSN1Set.size() > 0) {
                                            aSN1Encodable = (ASN1Primitive) aSN1Set.getObjectAt(0);
                                            bagAttribute = pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier);
                                            if (bagAttribute == null) {
                                                pKCS12BagAttributeCarrier.setBagAttribute(aSN1ObjectIdentifier, aSN1Encodable);
                                            } else if (!bagAttribute.toASN1Primitive().equals(aSN1Encodable)) {
                                                throw new IOException("attempt to add existing attribute with different value");
                                            }
                                        }
                                        aSN1Encodable = null;
                                        if (aSN1ObjectIdentifier.equals(pkcs_9_at_friendlyName)) {
                                            string = ((DERBMPString) aSN1Encodable).getString();
                                            this.keys.put(string, unwrapKey);
                                            str = string;
                                            aSN1OctetString2 = aSN1OctetString;
                                        } else if (aSN1ObjectIdentifier.equals(pkcs_9_at_localKeyId)) {
                                            aSN1OctetString2 = (ASN1OctetString) aSN1Encodable;
                                            str = str2;
                                        } else {
                                            aSN1OctetString2 = aSN1OctetString;
                                            str = str2;
                                        }
                                        aSN1OctetString = aSN1OctetString2;
                                        str2 = str;
                                    }
                                }
                                if (aSN1OctetString != null) {
                                    str3 = new String(Hex.encode(aSN1OctetString.getOctets()));
                                    if (obj5 == null) {
                                        this.keys.put(str3, unwrapKey);
                                    } else {
                                        this.localIds.put(obj5, str3);
                                    }
                                } else {
                                    obj3 = 1;
                                    this.keys.put("unmarked", unwrapKey);
                                }
                                obj4 = obj3;
                            } else if (instance2.getBagId().equals(certBag)) {
                                vector.addElement(instance2);
                                obj4 = obj3;
                            } else {
                                System.out.println("extra in data " + instance2.getBagId());
                                System.out.println(ASN1Dump.dumpAsString(instance2));
                                obj4 = obj3;
                            }
                            i2++;
                            obj3 = obj4;
                        }
                        obj2 = obj3;
                    } else if (contentInfo[i].getContentType().equals(encryptedData)) {
                        EncryptedData instance4 = EncryptedData.getInstance(contentInfo[i].getContent());
                        aSN1Sequence = (ASN1Sequence) ASN1Primitive.fromByteArray(cryptData(false, instance4.getEncryptionAlgorithm(), cArr, z, instance4.getContent().getOctets()));
                        for (int i3 = 0; i3 != aSN1Sequence.size(); i3++) {
                            instance2 = SafeBag.getInstance(aSN1Sequence.getObjectAt(i3));
                            if (instance2.getBagId().equals(certBag)) {
                                vector.addElement(instance2);
                            } else if (instance2.getBagId().equals(pkcs8ShroudedKeyBag)) {
                                instance3 = EncryptedPrivateKeyInfo.getInstance(instance2.getBagValue());
                                unwrapKey = unwrapKey(instance3.getEncryptionAlgorithm(), instance3.getEncryptedData(), cArr, z);
                                pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier) unwrapKey;
                                str2 = null;
                                aSN1OctetString = null;
                                objects = instance2.getBagAttributes().getObjects();
                                while (objects.hasMoreElements()) {
                                    aSN1Sequence2 = (ASN1Sequence) objects.nextElement();
                                    aSN1ObjectIdentifier = (ASN1ObjectIdentifier) aSN1Sequence2.getObjectAt(0);
                                    aSN1Set = (ASN1Set) aSN1Sequence2.getObjectAt(1);
                                    if (aSN1Set.size() > 0) {
                                        aSN1Encodable = (ASN1Primitive) aSN1Set.getObjectAt(0);
                                        bagAttribute = pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier);
                                        if (bagAttribute == null) {
                                            pKCS12BagAttributeCarrier.setBagAttribute(aSN1ObjectIdentifier, aSN1Encodable);
                                        } else if (!bagAttribute.toASN1Primitive().equals(aSN1Encodable)) {
                                            throw new IOException("attempt to add existing attribute with different value");
                                        }
                                    }
                                    aSN1Encodable = null;
                                    if (aSN1ObjectIdentifier.equals(pkcs_9_at_friendlyName)) {
                                        string = ((DERBMPString) aSN1Encodable).getString();
                                        this.keys.put(string, unwrapKey);
                                        str = string;
                                        aSN1OctetString2 = aSN1OctetString;
                                    } else if (aSN1ObjectIdentifier.equals(pkcs_9_at_localKeyId)) {
                                        aSN1OctetString2 = (ASN1OctetString) aSN1Encodable;
                                        str = str2;
                                    } else {
                                        aSN1OctetString2 = aSN1OctetString;
                                        str = str2;
                                    }
                                    aSN1OctetString = aSN1OctetString2;
                                    str2 = str;
                                }
                                str3 = new String(Hex.encode(aSN1OctetString.getOctets()));
                                if (str2 == null) {
                                    this.keys.put(str3, unwrapKey);
                                } else {
                                    this.localIds.put(str2, str3);
                                }
                            } else if (instance2.getBagId().equals(keyBag)) {
                                unwrapKey = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(instance2.getBagValue()));
                                pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier) unwrapKey;
                                str2 = null;
                                aSN1OctetString = null;
                                objects = instance2.getBagAttributes().getObjects();
                                while (objects.hasMoreElements()) {
                                    aSN1Sequence2 = (ASN1Sequence) objects.nextElement();
                                    aSN1ObjectIdentifier = (ASN1ObjectIdentifier) aSN1Sequence2.getObjectAt(0);
                                    aSN1Set = (ASN1Set) aSN1Sequence2.getObjectAt(1);
                                    if (aSN1Set.size() > 0) {
                                        aSN1Encodable = (ASN1Primitive) aSN1Set.getObjectAt(0);
                                        bagAttribute = pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier);
                                        if (bagAttribute == null) {
                                            pKCS12BagAttributeCarrier.setBagAttribute(aSN1ObjectIdentifier, aSN1Encodable);
                                        } else if (!bagAttribute.toASN1Primitive().equals(aSN1Encodable)) {
                                            throw new IOException("attempt to add existing attribute with different value");
                                        }
                                    }
                                    aSN1Encodable = null;
                                    if (aSN1ObjectIdentifier.equals(pkcs_9_at_friendlyName)) {
                                        string = ((DERBMPString) aSN1Encodable).getString();
                                        this.keys.put(string, unwrapKey);
                                        str = string;
                                        aSN1OctetString2 = aSN1OctetString;
                                    } else if (aSN1ObjectIdentifier.equals(pkcs_9_at_localKeyId)) {
                                        aSN1OctetString2 = (ASN1OctetString) aSN1Encodable;
                                        str = str2;
                                    } else {
                                        aSN1OctetString2 = aSN1OctetString;
                                        str = str2;
                                    }
                                    aSN1OctetString = aSN1OctetString2;
                                    str2 = str;
                                }
                                str3 = new String(Hex.encode(aSN1OctetString.getOctets()));
                                if (str2 == null) {
                                    this.keys.put(str3, unwrapKey);
                                } else {
                                    this.localIds.put(str2, str3);
                                }
                            } else {
                                System.out.println("extra in encryptedData " + instance2.getBagId());
                                System.out.println(ASN1Dump.dumpAsString(instance2));
                            }
                        }
                        obj2 = obj;
                    } else {
                        System.out.println("extra " + contentInfo[i].getContentType().getId());
                        System.out.println("extra " + ASN1Dump.dumpAsString(contentInfo[i].getContent()));
                        obj2 = obj;
                    }
                    i++;
                    obj = obj2;
                }
            }
            this.certs = new IgnoresCaseHashtable();
            this.chainCerts = new Hashtable();
            this.keyCerts = new Hashtable();
            int i4 = 0;
            while (i4 != vector.size()) {
                SafeBag safeBag = (SafeBag) vector.elementAt(i4);
                CertBag instance5 = CertBag.getInstance(safeBag.getBagValue());
                if (instance5.getCertId().equals(x509Certificate)) {
                    try {
                        String string2;
                        Certificate generateCertificate = this.certFact.generateCertificate(new ByteArrayInputStream(((ASN1OctetString) instance5.getCertValue()).getOctets()));
                        ASN1OctetString aSN1OctetString3 = null;
                        str = null;
                        if (safeBag.getBagAttributes() != null) {
                            Enumeration objects2 = safeBag.getBagAttributes().getObjects();
                            while (objects2.hasMoreElements()) {
                                ASN1OctetString aSN1OctetString4;
                                aSN1Sequence = (ASN1Sequence) objects2.nextElement();
                                ASN1ObjectIdentifier aSN1ObjectIdentifier2 = (ASN1ObjectIdentifier) aSN1Sequence.getObjectAt(0);
                                ASN1Primitive aSN1Primitive = (ASN1Primitive) ((ASN1Set) aSN1Sequence.getObjectAt(1)).getObjectAt(0);
                                if (generateCertificate instanceof PKCS12BagAttributeCarrier) {
                                    PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier2 = (PKCS12BagAttributeCarrier) generateCertificate;
                                    ASN1Encodable bagAttribute2 = pKCS12BagAttributeCarrier2.getBagAttribute(aSN1ObjectIdentifier2);
                                    if (bagAttribute2 == null) {
                                        pKCS12BagAttributeCarrier2.setBagAttribute(aSN1ObjectIdentifier2, aSN1Primitive);
                                    } else if (!bagAttribute2.toASN1Primitive().equals(aSN1Primitive)) {
                                        throw new IOException("attempt to add existing attribute with different value");
                                    }
                                }
                                if (aSN1ObjectIdentifier2.equals(pkcs_9_at_friendlyName)) {
                                    string2 = ((DERBMPString) aSN1Primitive).getString();
                                    aSN1OctetString4 = aSN1OctetString3;
                                } else if (aSN1ObjectIdentifier2.equals(pkcs_9_at_localKeyId)) {
                                    aSN1OctetString4 = (ASN1OctetString) aSN1Primitive;
                                    string2 = str;
                                } else {
                                    string2 = str;
                                    aSN1OctetString4 = aSN1OctetString3;
                                }
                                str = string2;
                                aSN1OctetString3 = aSN1OctetString4;
                            }
                        }
                        this.chainCerts.put(new CertId(generateCertificate.getPublicKey()), generateCertificate);
                        if (obj == null) {
                            if (aSN1OctetString3 != null) {
                                this.keyCerts.put(new String(Hex.encode(aSN1OctetString3.getOctets())), generateCertificate);
                            }
                            if (str != null) {
                                this.certs.put(str, generateCertificate);
                            }
                        } else if (this.keyCerts.isEmpty()) {
                            string2 = new String(Hex.encode(createSubjectKeyId(generateCertificate.getPublicKey()).getKeyIdentifier()));
                            this.keyCerts.put(string2, generateCertificate);
                            this.keys.put(string2, this.keys.remove("unmarked"));
                        }
                        i4++;
                    } catch (Exception e22) {
                        throw new RuntimeException(e22.toString());
                    }
                }
                throw new RuntimeException("Unsupported certificate type: " + instance5.getCertId());
            }
        }
    }

    public void engineSetCertificateEntry(String str, Certificate certificate) throws KeyStoreException {
        if (this.keys.get(str) != null) {
            throw new KeyStoreException("There is a key entry with the name " + str + ".");
        }
        this.certs.put(str, certificate);
        this.chainCerts.put(new CertId(certificate.getPublicKey()), certificate);
    }

    public void engineSetKeyEntry(String str, Key key, char[] cArr, Certificate[] certificateArr) throws KeyStoreException {
        int i = 0;
        if (!(key instanceof PrivateKey)) {
            throw new KeyStoreException("PKCS12 does not support non-PrivateKeys");
        } else if ((key instanceof PrivateKey) && certificateArr == null) {
            throw new KeyStoreException("no certificate chain for private key");
        } else {
            if (this.keys.get(str) != null) {
                engineDeleteEntry(str);
            }
            this.keys.put(str, key);
            if (certificateArr != null) {
                this.certs.put(str, certificateArr[0]);
                while (i != certificateArr.length) {
                    this.chainCerts.put(new CertId(certificateArr[i].getPublicKey()), certificateArr[i]);
                    i++;
                }
            }
        }
    }

    public void engineSetKeyEntry(String str, byte[] bArr, Certificate[] certificateArr) throws KeyStoreException {
        throw new RuntimeException("operation not supported");
    }

    public int engineSize() {
        Hashtable hashtable = new Hashtable();
        Enumeration keys = this.certs.keys();
        while (keys.hasMoreElements()) {
            hashtable.put(keys.nextElement(), "cert");
        }
        Enumeration keys2 = this.keys.keys();
        while (keys2.hasMoreElements()) {
            String str = (String) keys2.nextElement();
            if (hashtable.get(str) == null) {
                hashtable.put(str, "key");
            }
        }
        return hashtable.size();
    }

    public void engineStore(OutputStream outputStream, char[] cArr) throws IOException {
        doStore(outputStream, cArr, false);
    }

    public void engineStore(LoadStoreParameter loadStoreParameter) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (loadStoreParameter == null) {
            throw new IllegalArgumentException("'param' arg cannot be null");
        } else if ((loadStoreParameter instanceof PKCS12StoreParameter) || (loadStoreParameter instanceof JDKPKCS12StoreParameter)) {
            char[] cArr;
            PKCS12StoreParameter pKCS12StoreParameter = loadStoreParameter instanceof PKCS12StoreParameter ? (PKCS12StoreParameter) loadStoreParameter : new PKCS12StoreParameter(((JDKPKCS12StoreParameter) loadStoreParameter).getOutputStream(), loadStoreParameter.getProtectionParameter(), ((JDKPKCS12StoreParameter) loadStoreParameter).isUseDEREncoding());
            ProtectionParameter protectionParameter = loadStoreParameter.getProtectionParameter();
            if (protectionParameter == null) {
                cArr = null;
            } else if (protectionParameter instanceof PasswordProtection) {
                cArr = ((PasswordProtection) protectionParameter).getPassword();
            } else {
                throw new IllegalArgumentException("No support for protection parameter of type " + protectionParameter.getClass().getName());
            }
            doStore(pKCS12StoreParameter.getOutputStream(), cArr, pKCS12StoreParameter.isForDEREncoding());
        } else {
            throw new IllegalArgumentException("No support for 'param' of type " + loadStoreParameter.getClass().getName());
        }
    }

    public void setRandom(SecureRandom secureRandom) {
        this.random = secureRandom;
    }

    protected PrivateKey unwrapKey(AlgorithmIdentifier algorithmIdentifier, byte[] bArr, char[] cArr, boolean z) throws IOException {
        ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
        try {
            Key generateSecret;
            if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
                PKCS12PBEParams instance = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());
                KeySpec pBEKeySpec = new PBEKeySpec(cArr);
                SecretKeyFactory instance2 = SecretKeyFactory.getInstance(algorithm.getId(), bcProvider);
                AlgorithmParameterSpec pBEParameterSpec = new PBEParameterSpec(instance.getIV(), instance.getIterations().intValue());
                generateSecret = instance2.generateSecret(pBEKeySpec);
                ((BCPBEKey) generateSecret).setTryWrongPKCS12Zero(z);
                Cipher instance3 = Cipher.getInstance(algorithm.getId(), bcProvider);
                instance3.init(4, generateSecret, pBEParameterSpec);
                return (PrivateKey) instance3.unwrap(bArr, "", 2);
            } else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2)) {
                PBES2Parameters instance4 = PBES2Parameters.getInstance(algorithmIdentifier.getParameters());
                PBKDF2Params instance5 = PBKDF2Params.getInstance(instance4.getKeyDerivationFunc().getParameters());
                generateSecret = SecretKeyFactory.getInstance(instance4.getKeyDerivationFunc().getAlgorithm().getId(), bcProvider).generateSecret(new PBEKeySpec(cArr, instance5.getSalt(), instance5.getIterationCount().intValue(), SecretKeyUtil.getKeySize(instance4.getEncryptionScheme().getAlgorithm())));
                Cipher instance6 = Cipher.getInstance(instance4.getEncryptionScheme().getAlgorithm().getId(), bcProvider);
                instance6.init(4, generateSecret, new IvParameterSpec(ASN1OctetString.getInstance(instance4.getEncryptionScheme().getParameters()).getOctets()));
                return (PrivateKey) instance6.unwrap(bArr, "", 2);
            } else {
                throw new IOException("exception unwrapping private key - cannot recognise: " + algorithm);
            }
        } catch (Exception e) {
            throw new IOException("exception unwrapping private key - " + e.toString());
        }
    }

    protected byte[] wrapKey(String str, Key key, PKCS12PBEParams pKCS12PBEParams, char[] cArr) throws IOException {
        KeySpec pBEKeySpec = new PBEKeySpec(cArr);
        try {
            SecretKeyFactory instance = SecretKeyFactory.getInstance(str, bcProvider);
            AlgorithmParameterSpec pBEParameterSpec = new PBEParameterSpec(pKCS12PBEParams.getIV(), pKCS12PBEParams.getIterations().intValue());
            Cipher instance2 = Cipher.getInstance(str, bcProvider);
            instance2.init(3, instance.generateSecret(pBEKeySpec), pBEParameterSpec);
            return instance2.wrap(key);
        } catch (Exception e) {
            throw new IOException("exception encrypting data - " + e.toString());
        }
    }
}
