package org.spongycastle.jce.provider;

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
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.BERConstructedOctetString;
import org.spongycastle.asn1.BEROutputStream;
import org.spongycastle.asn1.DERBMPString;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DEROutputStream;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.pkcs.AuthenticatedSafe;
import org.spongycastle.asn1.pkcs.CertBag;
import org.spongycastle.asn1.pkcs.ContentInfo;
import org.spongycastle.asn1.pkcs.EncryptedData;
import org.spongycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.spongycastle.asn1.pkcs.MacData;
import org.spongycastle.asn1.pkcs.PKCS12PBEParams;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.pkcs.Pfx;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.pkcs.SafeBag;
import org.spongycastle.asn1.util.ASN1Dump;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.AuthorityKeyIdentifier;
import org.spongycastle.asn1.x509.DigestInfo;
import org.spongycastle.asn1.x509.SubjectKeyIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.X509Extensions;
import org.spongycastle.asn1.x509.X509ObjectIdentifiers;
import org.spongycastle.jce.interfaces.BCKeyStore;
import org.spongycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.Strings;
import org.spongycastle.util.encoders.Hex;

public class JDKPKCS12KeyStore extends KeyStoreSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers, BCKeyStore {
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
    private DERObjectIdentifier certAlgorithm;
    private CertificateFactory certFact;
    private IgnoresCaseHashtable certs = new IgnoresCaseHashtable();
    private Hashtable chainCerts = new Hashtable();
    private DERObjectIdentifier keyAlgorithm;
    private Hashtable keyCerts = new Hashtable();
    private IgnoresCaseHashtable keys = new IgnoresCaseHashtable();
    private Hashtable localIds = new Hashtable();
    protected SecureRandom random = new SecureRandom();

    private class CertId {
        byte[] id;

        CertId(PublicKey key) {
            this.id = JDKPKCS12KeyStore.this.createSubjectKeyId(key).getKeyIdentifier();
        }

        CertId(byte[] id) {
            this.id = id;
        }

        public int hashCode() {
            return Arrays.hashCode(this.id);
        }

        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (!(o instanceof CertId)) {
                return false;
            }
            return Arrays.areEqual(this.id, ((CertId) o).id);
        }
    }

    private static class IgnoresCaseHashtable {
        private Hashtable keys;
        private Hashtable orig;

        private IgnoresCaseHashtable() {
            this.orig = new Hashtable();
            this.keys = new Hashtable();
        }

        public void put(String key, Object value) {
            String lower = Strings.toLowerCase(key);
            String k = (String) this.keys.get(lower);
            if (k != null) {
                this.orig.remove(k);
            }
            this.keys.put(lower, key);
            this.orig.put(key, value);
        }

        public Enumeration keys() {
            return this.orig.keys();
        }

        public Object remove(String alias) {
            String k = (String) this.keys.remove(Strings.toLowerCase(alias));
            if (k == null) {
                return null;
            }
            return this.orig.remove(k);
        }

        public Object get(String alias) {
            String k = (String) this.keys.get(Strings.toLowerCase(alias));
            if (k == null) {
                return null;
            }
            return this.orig.get(k);
        }

        public Enumeration elements() {
            return this.orig.elements();
        }
    }

    public static class BCPKCS12KeyStore3DES extends JDKPKCS12KeyStore {
        public BCPKCS12KeyStore3DES() {
            super(JDKPKCS12KeyStore.bcProvider, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC);
        }
    }

    public static class BCPKCS12KeyStore extends JDKPKCS12KeyStore {
        public BCPKCS12KeyStore() {
            super(JDKPKCS12KeyStore.bcProvider, pbeWithSHAAnd3_KeyTripleDES_CBC, pbewithSHAAnd40BitRC2_CBC);
        }
    }

    public static class DefPKCS12KeyStore3DES extends JDKPKCS12KeyStore {
        public DefPKCS12KeyStore3DES() {
            super(null, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC);
        }
    }

    public static class DefPKCS12KeyStore extends JDKPKCS12KeyStore {
        public DefPKCS12KeyStore() {
            super(null, pbeWithSHAAnd3_KeyTripleDES_CBC, pbewithSHAAnd40BitRC2_CBC);
        }
    }

    public JDKPKCS12KeyStore(Provider provider, DERObjectIdentifier keyAlgorithm, DERObjectIdentifier certAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        this.certAlgorithm = certAlgorithm;
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

    private SubjectKeyIdentifier createSubjectKeyId(PublicKey pubKey) {
        try {
            return new SubjectKeyIdentifier(new SubjectPublicKeyInfo((ASN1Sequence) ASN1Object.fromByteArray(pubKey.getEncoded())));
        } catch (Exception e) {
            throw new RuntimeException("error creating key");
        }
    }

    public void setRandom(SecureRandom rand) {
        this.random = rand;
    }

    public Enumeration engineAliases() {
        Hashtable tab = new Hashtable();
        Enumeration e = this.certs.keys();
        while (e.hasMoreElements()) {
            tab.put(e.nextElement(), "cert");
        }
        e = this.keys.keys();
        while (e.hasMoreElements()) {
            String a = (String) e.nextElement();
            if (tab.get(a) == null) {
                tab.put(a, "key");
            }
        }
        return tab.keys();
    }

    public boolean engineContainsAlias(String alias) {
        return (this.certs.get(alias) == null && this.keys.get(alias) == null) ? false : true;
    }

    public void engineDeleteEntry(String alias) throws KeyStoreException {
        Key k = (Key) this.keys.remove(alias);
        Certificate c = (Certificate) this.certs.remove(alias);
        if (c != null) {
            this.chainCerts.remove(new CertId(c.getPublicKey()));
        }
        if (k != null) {
            String id = (String) this.localIds.remove(alias);
            if (id != null) {
                c = (Certificate) this.keyCerts.remove(id);
            }
            if (c != null) {
                this.chainCerts.remove(new CertId(c.getPublicKey()));
            }
        }
        if (c == null && k == null) {
            throw new KeyStoreException("no such entry as " + alias);
        }
    }

    public Certificate engineGetCertificate(String alias) {
        if (alias == null) {
            throw new IllegalArgumentException("null alias passed to getCertificate.");
        }
        Certificate c = (Certificate) this.certs.get(alias);
        if (c != null) {
            return c;
        }
        String id = (String) this.localIds.get(alias);
        if (id != null) {
            return (Certificate) this.keyCerts.get(id);
        }
        return (Certificate) this.keyCerts.get(alias);
    }

    public String engineGetCertificateAlias(Certificate cert) {
        Enumeration c = this.certs.elements();
        Enumeration k = this.certs.keys();
        while (c.hasMoreElements()) {
            String ta = (String) k.nextElement();
            if (((Certificate) c.nextElement()).equals(cert)) {
                return ta;
            }
        }
        c = this.keyCerts.elements();
        k = this.keyCerts.keys();
        while (c.hasMoreElements()) {
            ta = (String) k.nextElement();
            if (((Certificate) c.nextElement()).equals(cert)) {
                return ta;
            }
        }
        return null;
    }

    public Certificate[] engineGetCertificateChain(String alias) {
        if (alias == null) {
            throw new IllegalArgumentException("null alias passed to getCertificateChain.");
        } else if (!engineIsKeyEntry(alias)) {
            return null;
        } else {
            Certificate c = engineGetCertificate(alias);
            if (c == null) {
                return null;
            }
            Principal i;
            Vector cs = new Vector();
            while (c != null) {
                Enumeration e;
                X509Certificate x509c = (X509Certificate) c;
                Certificate nextC = null;
                byte[] bytes = x509c.getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId());
                if (bytes != null) {
                    try {
                        AuthorityKeyIdentifier id = new AuthorityKeyIdentifier((ASN1Sequence) new ASN1InputStream(((ASN1OctetString) new ASN1InputStream(bytes).readObject()).getOctets()).readObject());
                        if (id.getKeyIdentifier() != null) {
                            nextC = (Certificate) this.chainCerts.get(new CertId(id.getKeyIdentifier()));
                        }
                    } catch (Enumeration e2) {
                        throw new RuntimeException(e2.toString());
                    }
                }
                if (nextC == null) {
                    i = x509c.getIssuerDN();
                    if (!i.equals(x509c.getSubjectDN())) {
                        e2 = this.chainCerts.keys();
                        while (e2.hasMoreElements()) {
                            Certificate crt = (X509Certificate) this.chainCerts.get(e2.nextElement());
                            if (crt.getSubjectDN().equals(i)) {
                                try {
                                    x509c.verify(crt.getPublicKey());
                                    nextC = crt;
                                    break;
                                } catch (Exception e3) {
                                }
                            }
                        }
                    }
                }
                cs.addElement(c);
                if (nextC != c) {
                    c = nextC;
                } else {
                    c = null;
                }
            }
            Certificate[] certChain = new Certificate[cs.size()];
            for (i = null; i != certChain.length; i++) {
                certChain[i] = (Certificate) cs.elementAt(i);
            }
            return certChain;
        }
    }

    public Date engineGetCreationDate(String alias) {
        return new Date();
    }

    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        if (alias != null) {
            return (Key) this.keys.get(alias);
        }
        throw new IllegalArgumentException("null alias passed to getKey.");
    }

    public boolean engineIsCertificateEntry(String alias) {
        return this.certs.get(alias) != null && this.keys.get(alias) == null;
    }

    public boolean engineIsKeyEntry(String alias) {
        return this.keys.get(alias) != null;
    }

    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        if (this.keys.get(alias) != null) {
            throw new KeyStoreException("There is a key entry with the name " + alias + ".");
        }
        this.certs.put(alias, cert);
        this.chainCerts.put(new CertId(cert.getPublicKey()), cert);
    }

    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new RuntimeException("operation not supported");
    }

    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        if ((key instanceof PrivateKey) && chain == null) {
            throw new KeyStoreException("no certificate chain for private key");
        }
        if (this.keys.get(alias) != null) {
            engineDeleteEntry(alias);
        }
        this.keys.put(alias, key);
        this.certs.put(alias, chain[0]);
        for (int i = 0; i != chain.length; i++) {
            this.chainCerts.put(new CertId(chain[i].getPublicKey()), chain[i]);
        }
    }

    public int engineSize() {
        Hashtable tab = new Hashtable();
        Enumeration e = this.certs.keys();
        while (e.hasMoreElements()) {
            tab.put(e.nextElement(), "cert");
        }
        e = this.keys.keys();
        while (e.hasMoreElements()) {
            String a = (String) e.nextElement();
            if (tab.get(a) == null) {
                tab.put(a, "key");
            }
        }
        return tab.size();
    }

    protected PrivateKey unwrapKey(AlgorithmIdentifier algId, byte[] data, char[] password, boolean wrongPKCS12Zero) throws IOException {
        String algorithm = algId.getObjectId().getId();
        PKCS12PBEParams pbeParams = new PKCS12PBEParams((ASN1Sequence) algId.getParameters());
        PBEKeySpec pbeSpec = new PBEKeySpec(password);
        try {
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm, bcProvider);
            PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());
            SecretKey k = keyFact.generateSecret(pbeSpec);
            ((JCEPBEKey) k).setTryWrongPKCS12Zero(wrongPKCS12Zero);
            Cipher cipher = Cipher.getInstance(algorithm, bcProvider);
            cipher.init(4, k, defParams);
            return (PrivateKey) cipher.unwrap(data, "", 2);
        } catch (Exception e) {
            throw new IOException("exception unwrapping private key - " + e.toString());
        }
    }

    protected byte[] wrapKey(String algorithm, Key key, PKCS12PBEParams pbeParams, char[] password) throws IOException {
        PBEKeySpec pbeSpec = new PBEKeySpec(password);
        try {
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm, bcProvider);
            PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());
            Cipher cipher = Cipher.getInstance(algorithm, bcProvider);
            cipher.init(3, keyFact.generateSecret(pbeSpec), defParams);
            return cipher.wrap(key);
        } catch (Exception e) {
            throw new IOException("exception encrypting data - " + e.toString());
        }
    }

    protected byte[] cryptData(boolean forEncryption, AlgorithmIdentifier algId, char[] password, boolean wrongPKCS12Zero, byte[] data) throws IOException {
        String algorithm = algId.getObjectId().getId();
        PKCS12PBEParams pbeParams = new PKCS12PBEParams((ASN1Sequence) algId.getParameters());
        PBEKeySpec pbeSpec = new PBEKeySpec(password);
        try {
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm, bcProvider);
            PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());
            JCEPBEKey key = (JCEPBEKey) keyFact.generateSecret(pbeSpec);
            key.setTryWrongPKCS12Zero(wrongPKCS12Zero);
            Cipher cipher = Cipher.getInstance(algorithm, bcProvider);
            cipher.init(forEncryption ? 1 : 2, key, defParams);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new IOException("exception decrypting data - " + e.toString());
        }
    }

    public void engineLoad(InputStream stream, char[] password) throws IOException {
        if (stream != null) {
            if (password == null) {
                throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
            }
            InputStream bufferedInputStream = new BufferedInputStream(stream);
            bufferedInputStream.mark(10);
            if (bufferedInputStream.read() != 48) {
                throw new IOException("stream does not represent a PKCS12 key store");
            }
            int i;
            PKCS12BagAttributeCarrier bagAttr;
            String alias;
            ASN1OctetString localId;
            Enumeration e;
            ASN1Sequence sq;
            DERObject attr;
            DEREncodable existing;
            String str;
            bufferedInputStream.reset();
            Pfx pfx = new Pfx((ASN1Sequence) new ASN1InputStream(bufferedInputStream).readObject());
            ContentInfo info = pfx.getAuthSafe();
            Vector chain = new Vector();
            boolean unmarkedKey = false;
            boolean wrongPKCS12Zero = false;
            if (pfx.getMacData() != null) {
                MacData mData = pfx.getMacData();
                DigestInfo dInfo = mData.getMac();
                AlgorithmIdentifier algId = dInfo.getAlgorithmId();
                byte[] salt = mData.getSalt();
                int itCount = mData.getIterationCount().intValue();
                byte[] data = ((ASN1OctetString) info.getContent()).getOctets();
                try {
                    byte[] res = calculatePbeMac(algId.getObjectId(), salt, itCount, password, false, data);
                    byte[] dig = dInfo.getDigest();
                    if (!Arrays.constantTimeAreEqual(res, dig)) {
                        if (password.length > 0) {
                            throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                        } else if (Arrays.constantTimeAreEqual(calculatePbeMac(algId.getObjectId(), salt, itCount, password, true, data), dig)) {
                            wrongPKCS12Zero = true;
                        } else {
                            throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                        }
                    }
                } catch (IOException e2) {
                    throw e2;
                } catch (Exception e3) {
                    throw new IOException("error constructing MAC: " + e3.toString());
                }
            }
            this.keys = new IgnoresCaseHashtable();
            this.localIds = new Hashtable();
            if (info.getContentType().equals(data)) {
                ContentInfo[] c = new AuthenticatedSafe((ASN1Sequence) new ASN1InputStream(((ASN1OctetString) info.getContent()).getOctets()).readObject()).getContentInfo();
                for (i = 0; i != c.length; i++) {
                    ASN1Sequence seq;
                    int j;
                    SafeBag safeBag;
                    EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;
                    PrivateKey privKey;
                    DERObjectIdentifier aOid;
                    ASN1Set attrSet;
                    if (c[i].getContentType().equals(data)) {
                        seq = (ASN1Sequence) new ASN1InputStream(((ASN1OctetString) c[i].getContent()).getOctets()).readObject();
                        for (j = 0; j != seq.size(); j++) {
                            safeBag = new SafeBag((ASN1Sequence) seq.getObjectAt(j));
                            if (safeBag.getBagId().equals(pkcs8ShroudedKeyBag)) {
                                encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo((ASN1Sequence) safeBag.getBagValue());
                                privKey = unwrapKey(encryptedPrivateKeyInfo.getEncryptionAlgorithm(), encryptedPrivateKeyInfo.getEncryptedData(), password, wrongPKCS12Zero);
                                bagAttr = (PKCS12BagAttributeCarrier) privKey;
                                alias = null;
                                localId = null;
                                if (safeBag.getBagAttributes() != null) {
                                    e = safeBag.getBagAttributes().getObjects();
                                    while (e.hasMoreElements()) {
                                        sq = (ASN1Sequence) e.nextElement();
                                        aOid = (DERObjectIdentifier) sq.getObjectAt(0);
                                        attrSet = (ASN1Set) sq.getObjectAt(1);
                                        attr = null;
                                        if (attrSet.size() > 0) {
                                            attr = (DERObject) attrSet.getObjectAt(0);
                                            existing = bagAttr.getBagAttribute(aOid);
                                            if (existing == null) {
                                                bagAttr.setBagAttribute(aOid, attr);
                                            } else if (!existing.getDERObject().equals(attr)) {
                                                throw new IOException("attempt to add existing attribute with different value");
                                            }
                                        }
                                        if (aOid.equals(pkcs_9_at_friendlyName)) {
                                            alias = ((DERBMPString) attr).getString();
                                            this.keys.put(alias, privKey);
                                        } else if (aOid.equals(pkcs_9_at_localKeyId)) {
                                            localId = (ASN1OctetString) attr;
                                        }
                                    }
                                }
                                if (localId != null) {
                                    str = new String(Hex.encode(localId.getOctets()));
                                    if (alias == null) {
                                        this.keys.put(str, privKey);
                                    } else {
                                        this.localIds.put(alias, str);
                                    }
                                } else {
                                    unmarkedKey = true;
                                    this.keys.put("unmarked", privKey);
                                }
                            } else if (safeBag.getBagId().equals(certBag)) {
                                chain.addElement(safeBag);
                            } else {
                                System.out.println("extra in data " + safeBag.getBagId());
                                System.out.println(ASN1Dump.dumpAsString(safeBag));
                            }
                        }
                        continue;
                    } else if (c[i].getContentType().equals(encryptedData)) {
                        EncryptedData encryptedData = new EncryptedData((ASN1Sequence) c[i].getContent());
                        seq = (ASN1Sequence) ASN1Object.fromByteArray(cryptData(false, encryptedData.getEncryptionAlgorithm(), password, wrongPKCS12Zero, encryptedData.getContent().getOctets()));
                        for (j = 0; j != seq.size(); j++) {
                            safeBag = new SafeBag((ASN1Sequence) seq.getObjectAt(j));
                            if (safeBag.getBagId().equals(certBag)) {
                                chain.addElement(safeBag);
                            } else if (safeBag.getBagId().equals(pkcs8ShroudedKeyBag)) {
                                encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo((ASN1Sequence) safeBag.getBagValue());
                                privKey = unwrapKey(encryptedPrivateKeyInfo.getEncryptionAlgorithm(), encryptedPrivateKeyInfo.getEncryptedData(), password, wrongPKCS12Zero);
                                bagAttr = (PKCS12BagAttributeCarrier) privKey;
                                alias = null;
                                localId = null;
                                e = safeBag.getBagAttributes().getObjects();
                                while (e.hasMoreElements()) {
                                    sq = (ASN1Sequence) e.nextElement();
                                    aOid = (DERObjectIdentifier) sq.getObjectAt(0);
                                    attrSet = (ASN1Set) sq.getObjectAt(1);
                                    attr = null;
                                    if (attrSet.size() > 0) {
                                        attr = (DERObject) attrSet.getObjectAt(0);
                                        existing = bagAttr.getBagAttribute(aOid);
                                        if (existing == null) {
                                            bagAttr.setBagAttribute(aOid, attr);
                                        } else if (!existing.getDERObject().equals(attr)) {
                                            throw new IOException("attempt to add existing attribute with different value");
                                        }
                                    }
                                    if (aOid.equals(pkcs_9_at_friendlyName)) {
                                        alias = ((DERBMPString) attr).getString();
                                        this.keys.put(alias, privKey);
                                    } else if (aOid.equals(pkcs_9_at_localKeyId)) {
                                        localId = (ASN1OctetString) attr;
                                    }
                                }
                                str = new String(Hex.encode(localId.getOctets()));
                                if (alias == null) {
                                    this.keys.put(str, privKey);
                                } else {
                                    this.localIds.put(alias, str);
                                }
                            } else if (safeBag.getBagId().equals(keyBag)) {
                                privKey = JDKKeyFactory.createPrivateKeyFromPrivateKeyInfo(new PrivateKeyInfo((ASN1Sequence) safeBag.getBagValue()));
                                bagAttr = (PKCS12BagAttributeCarrier) privKey;
                                alias = null;
                                localId = null;
                                e = safeBag.getBagAttributes().getObjects();
                                while (e.hasMoreElements()) {
                                    sq = (ASN1Sequence) e.nextElement();
                                    aOid = (DERObjectIdentifier) sq.getObjectAt(0);
                                    attrSet = (ASN1Set) sq.getObjectAt(1);
                                    attr = null;
                                    if (attrSet.size() > 0) {
                                        attr = (DERObject) attrSet.getObjectAt(0);
                                        existing = bagAttr.getBagAttribute(aOid);
                                        if (existing == null) {
                                            bagAttr.setBagAttribute(aOid, attr);
                                        } else if (!existing.getDERObject().equals(attr)) {
                                            throw new IOException("attempt to add existing attribute with different value");
                                        }
                                    }
                                    if (aOid.equals(pkcs_9_at_friendlyName)) {
                                        alias = ((DERBMPString) attr).getString();
                                        this.keys.put(alias, privKey);
                                    } else if (aOid.equals(pkcs_9_at_localKeyId)) {
                                        localId = (ASN1OctetString) attr;
                                    }
                                }
                                str = new String(Hex.encode(localId.getOctets()));
                                if (alias == null) {
                                    this.keys.put(str, privKey);
                                } else {
                                    this.localIds.put(alias, str);
                                }
                            } else {
                                System.out.println("extra in encryptedData " + safeBag.getBagId());
                                System.out.println(ASN1Dump.dumpAsString(safeBag));
                            }
                        }
                        continue;
                    } else {
                        System.out.println("extra " + c[i].getContentType().getId());
                        System.out.println("extra " + ASN1Dump.dumpAsString(c[i].getContent()));
                    }
                }
            }
            this.certs = new IgnoresCaseHashtable();
            this.chainCerts = new Hashtable();
            this.keyCerts = new Hashtable();
            i = 0;
            while (i != chain.size()) {
                SafeBag b = (SafeBag) chain.elementAt(i);
                CertBag certBag = new CertBag((ASN1Sequence) b.getBagValue());
                if (certBag.getCertId().equals(x509Certificate)) {
                    try {
                        Certificate cert = this.certFact.generateCertificate(new ByteArrayInputStream(((ASN1OctetString) certBag.getCertValue()).getOctets()));
                        localId = null;
                        alias = null;
                        if (b.getBagAttributes() != null) {
                            e = b.getBagAttributes().getObjects();
                            while (e.hasMoreElements()) {
                                sq = (ASN1Sequence) e.nextElement();
                                DERObjectIdentifier oid = (DERObjectIdentifier) sq.getObjectAt(0);
                                attr = (DERObject) ((ASN1Set) sq.getObjectAt(1)).getObjectAt(0);
                                if (cert instanceof PKCS12BagAttributeCarrier) {
                                    bagAttr = (PKCS12BagAttributeCarrier) cert;
                                    existing = bagAttr.getBagAttribute(oid);
                                    if (existing == null) {
                                        bagAttr.setBagAttribute(oid, attr);
                                    } else if (!existing.getDERObject().equals(attr)) {
                                        throw new IOException("attempt to add existing attribute with different value");
                                    }
                                }
                                if (oid.equals(pkcs_9_at_friendlyName)) {
                                    alias = ((DERBMPString) attr).getString();
                                } else {
                                    if (oid.equals(pkcs_9_at_localKeyId)) {
                                        localId = (ASN1OctetString) attr;
                                    }
                                }
                            }
                        }
                        this.chainCerts.put(new CertId(cert.getPublicKey()), cert);
                        if (!unmarkedKey) {
                            if (localId != null) {
                                this.keyCerts.put(new String(Hex.encode(localId.getOctets())), cert);
                            }
                            if (alias != null) {
                                this.certs.put(alias, cert);
                            }
                        } else if (this.keyCerts.isEmpty()) {
                            str = new String(Hex.encode(createSubjectKeyId(cert.getPublicKey()).getKeyIdentifier()));
                            this.keyCerts.put(str, cert);
                            this.keys.put(str, this.keys.remove("unmarked"));
                        }
                        i++;
                    } catch (Enumeration e4) {
                        throw new RuntimeException(e4.toString());
                    }
                }
                throw new RuntimeException("Unsupported certificate type: " + certBag.getCertId());
            }
        }
    }

    public void engineStore(LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (param == null) {
            throw new IllegalArgumentException("'param' arg cannot be null");
        } else if (param instanceof JDKPKCS12StoreParameter) {
            char[] password;
            JDKPKCS12StoreParameter bcParam = (JDKPKCS12StoreParameter) param;
            ProtectionParameter protParam = param.getProtectionParameter();
            if (protParam == null) {
                password = null;
            } else if (protParam instanceof PasswordProtection) {
                password = ((PasswordProtection) protParam).getPassword();
            } else {
                throw new IllegalArgumentException("No support for protection parameter of type " + protParam.getClass().getName());
            }
            doStore(bcParam.getOutputStream(), password, bcParam.isUseDEREncoding());
        } else {
            throw new IllegalArgumentException("No support for 'param' of type " + param.getClass().getName());
        }
    }

    public void engineStore(OutputStream stream, char[] password) throws IOException {
        doStore(stream, password, false);
    }

    private void doStore(OutputStream stream, char[] password, boolean useDEREncoding) throws IOException {
        if (password == null) {
            throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
        }
        PKCS12BagAttributeCarrier bagAttrs;
        DERBMPString nm;
        Certificate cert;
        ASN1EncodableVector fName;
        ASN1EncodableVector fSeq;
        DEROutputStream dEROutputStream;
        ASN1EncodableVector keyS = new ASN1EncodableVector();
        Enumeration ks = this.keys.keys();
        while (ks.hasMoreElements()) {
            Enumeration e;
            byte[] kSalt = new byte[20];
            this.random.nextBytes(kSalt);
            String name = (String) ks.nextElement();
            PrivateKey privKey = (PrivateKey) this.keys.get(name);
            PKCS12PBEParams pKCS12PBEParams = new PKCS12PBEParams(kSalt, 1024);
            EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(this.keyAlgorithm, pKCS12PBEParams.getDERObject()), wrapKey(this.keyAlgorithm.getId(), privKey, pKCS12PBEParams, password));
            boolean attrSet = false;
            ASN1EncodableVector kName = new ASN1EncodableVector();
            if (privKey instanceof PKCS12BagAttributeCarrier) {
                bagAttrs = (PKCS12BagAttributeCarrier) privKey;
                nm = (DERBMPString) bagAttrs.getBagAttribute(pkcs_9_at_friendlyName);
                if (nm == null || !nm.getString().equals(name)) {
                    bagAttrs.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(name));
                }
                if (bagAttrs.getBagAttribute(pkcs_9_at_localKeyId) == null) {
                    Certificate ct = engineGetCertificate(name);
                    bagAttrs.setBagAttribute(pkcs_9_at_localKeyId, createSubjectKeyId(ct.getPublicKey()));
                }
                e = bagAttrs.getBagAttributeKeys();
                while (e.hasMoreElements()) {
                    DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                    ASN1EncodableVector kSeq = new ASN1EncodableVector();
                    kSeq.add(oid);
                    kSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));
                    attrSet = true;
                    kName.add(new DERSequence(kSeq));
                }
            }
            if (!attrSet) {
                kSeq = new ASN1EncodableVector();
                ct = engineGetCertificate(name);
                kSeq.add(pkcs_9_at_localKeyId);
                kSeq.add(new DERSet(createSubjectKeyId(ct.getPublicKey())));
                kName.add(new DERSequence(kSeq));
                kSeq = new ASN1EncodableVector();
                kSeq.add(pkcs_9_at_friendlyName);
                kSeq.add(new DERSet(new DERBMPString(name)));
                kName.add(new DERSequence(kSeq));
            }
            keyS.add(new SafeBag(pkcs8ShroudedKeyBag, encryptedPrivateKeyInfo.getDERObject(), new DERSet(kName)));
        }
        BERConstructedOctetString bERConstructedOctetString = new BERConstructedOctetString(new DERSequence(keyS).getDEREncoded());
        byte[] cSalt = new byte[20];
        this.random.nextBytes(cSalt);
        ASN1EncodableVector certSeq = new ASN1EncodableVector();
        AlgorithmIdentifier cAlgId = new AlgorithmIdentifier(this.certAlgorithm, new PKCS12PBEParams(cSalt, 1024).getDERObject());
        Hashtable doneCerts = new Hashtable();
        Enumeration cs = this.keys.keys();
        while (cs.hasMoreElements()) {
            boolean cAttrSet;
            try {
                name = (String) cs.nextElement();
                cert = engineGetCertificate(name);
                cAttrSet = false;
                CertBag certBag = new CertBag(x509Certificate, new DEROctetString(cert.getEncoded()));
                fName = new ASN1EncodableVector();
                if (cert instanceof PKCS12BagAttributeCarrier) {
                    bagAttrs = (PKCS12BagAttributeCarrier) cert;
                    nm = (DERBMPString) bagAttrs.getBagAttribute(pkcs_9_at_friendlyName);
                    if (nm == null || !nm.getString().equals(name)) {
                        bagAttrs.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(name));
                    }
                    if (bagAttrs.getBagAttribute(pkcs_9_at_localKeyId) == null) {
                        bagAttrs.setBagAttribute(pkcs_9_at_localKeyId, createSubjectKeyId(cert.getPublicKey()));
                    }
                    e = bagAttrs.getBagAttributeKeys();
                    while (e.hasMoreElements()) {
                        oid = (DERObjectIdentifier) e.nextElement();
                        fSeq = new ASN1EncodableVector();
                        fSeq.add(oid);
                        fSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));
                        fName.add(new DERSequence(fSeq));
                        cAttrSet = true;
                    }
                }
                if (!cAttrSet) {
                    fSeq = new ASN1EncodableVector();
                    fSeq.add(pkcs_9_at_localKeyId);
                    fSeq.add(new DERSet(createSubjectKeyId(cert.getPublicKey())));
                    fName.add(new DERSequence(fSeq));
                    fSeq = new ASN1EncodableVector();
                    fSeq.add(pkcs_9_at_friendlyName);
                    fSeq.add(new DERSet(new DERBMPString(name)));
                    fName.add(new DERSequence(fSeq));
                }
                certSeq.add(new SafeBag(certBag, certBag.getDERObject(), new DERSet(fName)));
                doneCerts.put(cert, cert);
            } catch (CertificateEncodingException e2) {
                throw new IOException("Error encoding certificate: " + e2.toString());
            }
        }
        cs = this.certs.keys();
        while (cs.hasMoreElements()) {
            try {
                String certId = (String) cs.nextElement();
                cert = (Certificate) this.certs.get(certId);
                cAttrSet = false;
                if (this.keys.get(certId) == null) {
                    certBag = new CertBag(x509Certificate, new DEROctetString(cert.getEncoded()));
                    fName = new ASN1EncodableVector();
                    if (cert instanceof PKCS12BagAttributeCarrier) {
                        bagAttrs = (PKCS12BagAttributeCarrier) cert;
                        nm = (DERBMPString) bagAttrs.getBagAttribute(pkcs_9_at_friendlyName);
                        if (nm == null || !nm.getString().equals(certId)) {
                            bagAttrs.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(certId));
                        }
                        e = bagAttrs.getBagAttributeKeys();
                        while (e.hasMoreElements()) {
                            oid = (DERObjectIdentifier) e.nextElement();
                            if (!oid.equals(PKCSObjectIdentifiers.pkcs_9_at_localKeyId)) {
                                fSeq = new ASN1EncodableVector();
                                fSeq.add(oid);
                                fSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));
                                fName.add(new DERSequence(fSeq));
                                cAttrSet = true;
                            }
                        }
                    }
                    if (!cAttrSet) {
                        fSeq = new ASN1EncodableVector();
                        fSeq.add(pkcs_9_at_friendlyName);
                        fSeq.add(new DERSet(new DERBMPString(certId)));
                        fName.add(new DERSequence(fSeq));
                    }
                    certSeq.add(new SafeBag(certBag, certBag.getDERObject(), new DERSet(fName)));
                    doneCerts.put(cert, cert);
                }
            } catch (CertificateEncodingException e22) {
                throw new IOException("Error encoding certificate: " + e22.toString());
            }
        }
        cs = this.chainCerts.keys();
        while (cs.hasMoreElements()) {
            try {
                cert = (Certificate) this.chainCerts.get((CertId) cs.nextElement());
                if (doneCerts.get(cert) == null) {
                    certBag = new CertBag(x509Certificate, new DEROctetString(cert.getEncoded()));
                    fName = new ASN1EncodableVector();
                    if (cert instanceof PKCS12BagAttributeCarrier) {
                        bagAttrs = (PKCS12BagAttributeCarrier) cert;
                        e = bagAttrs.getBagAttributeKeys();
                        while (e.hasMoreElements()) {
                            oid = (DERObjectIdentifier) e.nextElement();
                            if (!oid.equals(PKCSObjectIdentifiers.pkcs_9_at_localKeyId)) {
                                fSeq = new ASN1EncodableVector();
                                fSeq.add(oid);
                                fSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));
                                fName.add(new DERSequence(fSeq));
                            }
                        }
                    }
                    certSeq.add(new SafeBag(certBag, certBag.getDERObject(), new DERSet(fName)));
                }
            } catch (CertificateEncodingException e222) {
                throw new IOException("Error encoding certificate: " + e222.toString());
            }
        }
        EncryptedData encryptedData = new EncryptedData(data, cAlgId, new BERConstructedOctetString(cryptData(true, cAlgId, password, false, new DERSequence(certSeq).getDEREncoded())));
        AuthenticatedSafe authenticatedSafe = new AuthenticatedSafe(new ContentInfo[]{new ContentInfo(data, bERConstructedOctetString), new ContentInfo(encryptedData, encryptedData.getDERObject())});
        OutputStream bOut = new ByteArrayOutputStream();
        if (useDEREncoding) {
            dEROutputStream = new DEROutputStream(bOut);
        } else {
            dEROutputStream = new BEROutputStream(bOut);
        }
        asn1Out.writeObject(authenticatedSafe);
        ContentInfo contentInfo = new ContentInfo(data, new BERConstructedOctetString(bOut.toByteArray()));
        byte[] mSalt = new byte[20];
        this.random.nextBytes(mSalt);
        try {
            Pfx pfx = new Pfx(contentInfo, new MacData(new DigestInfo(new AlgorithmIdentifier(id_SHA1, new DERNull()), calculatePbeMac(id_SHA1, mSalt, 1024, password, false, ((ASN1OctetString) contentInfo.getContent()).getOctets())), mSalt, 1024));
            if (useDEREncoding) {
                dEROutputStream = new DEROutputStream(stream);
            } else {
                dEROutputStream = new BEROutputStream(stream);
            }
            asn1Out.writeObject(pfx);
        } catch (Exception e3) {
            throw new IOException("error constructing MAC: " + e3.toString());
        }
    }

    private static byte[] calculatePbeMac(DERObjectIdentifier oid, byte[] salt, int itCount, char[] password, boolean wrongPkcs12Zero, byte[] data) throws Exception {
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(oid.getId(), bcProvider);
        PBEParameterSpec defParams = new PBEParameterSpec(salt, itCount);
        JCEPBEKey key = (JCEPBEKey) keyFact.generateSecret(new PBEKeySpec(password));
        key.setTryWrongPKCS12Zero(wrongPkcs12Zero);
        Mac mac = Mac.getInstance(oid.getId(), bcProvider);
        mac.init(key, defParams);
        mac.update(data);
        return mac.doFinal();
    }
}
