package org.bouncycastle.openssl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectParser;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.x509.X509V2AttributeCertificate;

public class PEMReader extends PemReader {
    private PasswordFinder pFinder;
    private final Map parsers;

    private class ECNamedCurveSpecParser implements PemObjectParser {
        private ECNamedCurveSpecParser() {
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(((DERObjectIdentifier) ASN1Primitive.fromByteArray(pemObject.getContent())).getId());
                if (parameterSpec != null) {
                    return parameterSpec;
                }
                throw new IOException("object ID not found in EC curve table");
            } catch (IOException e) {
                throw e;
            } catch (Exception e2) {
                throw new PEMException("exception extracting EC named curve: " + e2.toString());
            }
        }
    }

    private class EncryptedPrivateKeyParser implements PemObjectParser {
        private String asymProvider;
        private String symProvider;

        public EncryptedPrivateKeyParser(String str, String str2) {
            this.symProvider = str;
            this.asymProvider = str2;
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                EncryptedPrivateKeyInfo instance = EncryptedPrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(pemObject.getContent()));
                AlgorithmIdentifier encryptionAlgorithm = instance.getEncryptionAlgorithm();
                if (PEMReader.this.pFinder == null) {
                    throw new PEMException("no PasswordFinder specified");
                } else if (PEMUtilities.isPKCS5Scheme2(encryptionAlgorithm.getAlgorithm())) {
                    PBES2Parameters instance2 = PBES2Parameters.getInstance(encryptionAlgorithm.getParameters());
                    KeyDerivationFunc keyDerivationFunc = instance2.getKeyDerivationFunc();
                    EncryptionScheme encryptionScheme = instance2.getEncryptionScheme();
                    PBKDF2Params pBKDF2Params = (PBKDF2Params) keyDerivationFunc.getParameters();
                    int intValue = pBKDF2Params.getIterationCount().intValue();
                    byte[] salt = pBKDF2Params.getSalt();
                    String id = encryptionScheme.getAlgorithm().getId();
                    Key generateSecretKeyForPKCS5Scheme2 = PEMReader.generateSecretKeyForPKCS5Scheme2(id, PEMReader.this.pFinder.getPassword(), salt, intValue);
                    Cipher instance3 = Cipher.getInstance(id, this.symProvider);
                    AlgorithmParameters instance4 = AlgorithmParameters.getInstance(id, this.symProvider);
                    instance4.init(encryptionScheme.getParameters().toASN1Primitive().getEncoded());
                    instance3.init(2, generateSecretKeyForPKCS5Scheme2, instance4);
                    r0 = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(instance3.doFinal(instance.getEncryptedData())));
                    return KeyFactory.getInstance(r0.getPrivateKeyAlgorithm().getAlgorithm().getId(), this.asymProvider).generatePrivate(new PKCS8EncodedKeySpec(r0.getEncoded()));
                } else if (PEMUtilities.isPKCS12(encryptionAlgorithm.getAlgorithm())) {
                    PKCS12PBEParams instance5 = PKCS12PBEParams.getInstance(encryptionAlgorithm.getParameters());
                    r0 = encryptionAlgorithm.getAlgorithm().getId();
                    r3 = new PBEKeySpec(PEMReader.this.pFinder.getPassword());
                    r4 = SecretKeyFactory.getInstance(r0, this.symProvider);
                    r5 = new PBEParameterSpec(instance5.getIV(), instance5.getIterations().intValue());
                    r0 = Cipher.getInstance(r0, this.symProvider);
                    r0.init(2, r4.generateSecret(r3), r5);
                    r0 = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(r0.doFinal(instance.getEncryptedData())));
                    return KeyFactory.getInstance(r0.getPrivateKeyAlgorithm().getAlgorithm().getId(), this.asymProvider).generatePrivate(new PKCS8EncodedKeySpec(r0.getEncoded()));
                } else if (PEMUtilities.isPKCS5Scheme1(encryptionAlgorithm.getAlgorithm())) {
                    PBEParameter instance6 = PBEParameter.getInstance(encryptionAlgorithm.getParameters());
                    r0 = encryptionAlgorithm.getAlgorithm().getId();
                    r3 = new PBEKeySpec(PEMReader.this.pFinder.getPassword());
                    r4 = SecretKeyFactory.getInstance(r0, this.symProvider);
                    r5 = new PBEParameterSpec(instance6.getSalt(), instance6.getIterationCount().intValue());
                    r0 = Cipher.getInstance(r0, this.symProvider);
                    r0.init(2, r4.generateSecret(r3), r5);
                    r0 = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(r0.doFinal(instance.getEncryptedData())));
                    return KeyFactory.getInstance(r0.getPrivateKeyAlgorithm().getAlgorithm().getId(), this.asymProvider).generatePrivate(new PKCS8EncodedKeySpec(r0.getEncoded()));
                } else {
                    throw new PEMException("Unknown algorithm: " + encryptionAlgorithm.getAlgorithm());
                }
            } catch (IOException e) {
                throw e;
            } catch (Exception e2) {
                throw new PEMException("problem parsing ENCRYPTED PRIVATE KEY: " + e2.toString(), e2);
            }
        }
    }

    private abstract class KeyPairParser implements PemObjectParser {
        protected String symProvider;

        public KeyPairParser(String str) {
            this.symProvider = str;
        }

        protected ASN1Sequence readKeyPair(PemObject pemObject) throws IOException {
            String str = null;
            boolean z = false;
            for (PemHeader pemHeader : pemObject.getHeaders()) {
                boolean z2;
                String str2;
                if (pemHeader.getName().equals("Proc-Type") && pemHeader.getValue().equals("4,ENCRYPTED")) {
                    z2 = true;
                    str2 = str;
                } else if (pemHeader.getName().equals("DEK-Info")) {
                    str2 = pemHeader.getValue();
                    z2 = z;
                } else {
                    str2 = str;
                    z2 = z;
                }
                str = str2;
                z = z2;
            }
            byte[] content = pemObject.getContent();
            if (z) {
                if (PEMReader.this.pFinder == null) {
                    throw new PasswordException("No password finder specified, but a password is required");
                }
                char[] password = PEMReader.this.pFinder.getPassword();
                if (password == null) {
                    throw new PasswordException("Password is null, but a password is required");
                }
                StringTokenizer stringTokenizer = new StringTokenizer(str, ",");
                content = PEMReader.crypt(false, this.symProvider, content, password, stringTokenizer.nextToken(), Hex.decode(stringTokenizer.nextToken()));
            }
            try {
                return ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(content));
            } catch (Exception e) {
                if (z) {
                    throw new PEMException("exception decoding - please check password and data.", e);
                }
                throw new PEMException(e.getMessage(), e);
            } catch (Exception e2) {
                if (z) {
                    throw new PEMException("exception decoding - please check password and data.", e2);
                }
                throw new PEMException(e2.getMessage(), e2);
            }
        }
    }

    private class PKCS10CertificationRequestParser implements PemObjectParser {
        private PKCS10CertificationRequestParser() {
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                return new PKCS10CertificationRequest(pemObject.getContent());
            } catch (Exception e) {
                throw new PEMException("problem parsing certrequest: " + e.toString(), e);
            }
        }
    }

    private class PKCS7Parser implements PemObjectParser {
        private PKCS7Parser() {
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                return ContentInfo.getInstance(new ASN1InputStream(pemObject.getContent()).readObject());
            } catch (Exception e) {
                throw new PEMException("problem parsing PKCS7 object: " + e.toString(), e);
            }
        }
    }

    private class PrivateKeyParser implements PemObjectParser {
        private String provider;

        public PrivateKeyParser(String str) {
            this.provider = str;
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                PrivateKeyInfo instance = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(pemObject.getContent()));
                return KeyFactory.getInstance(instance.getPrivateKeyAlgorithm().getAlgorithm().getId(), this.provider).generatePrivate(new PKCS8EncodedKeySpec(pemObject.getContent()));
            } catch (Exception e) {
                throw new PEMException("problem parsing PRIVATE KEY: " + e.toString(), e);
            }
        }
    }

    private class PublicKeyParser implements PemObjectParser {
        private String provider;

        public PublicKeyParser(String str) {
            this.provider = str;
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            int i = 0;
            KeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pemObject.getContent());
            String[] strArr = new String[]{"DSA", "RSA"};
            while (i < strArr.length) {
                try {
                    return KeyFactory.getInstance(strArr[i], this.provider).generatePublic(x509EncodedKeySpec);
                } catch (NoSuchAlgorithmException e) {
                } catch (InvalidKeySpecException e2) {
                } catch (NoSuchProviderException e3) {
                    throw new RuntimeException("can't find provider " + this.provider);
                }
            }
            return null;
            i++;
        }
    }

    private class RSAPublicKeyParser implements PemObjectParser {
        private String provider;

        public RSAPublicKeyParser(String str) {
            this.provider = str;
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                RSAPublicKey instance = RSAPublicKey.getInstance((ASN1Sequence) new ASN1InputStream(pemObject.getContent()).readObject());
                return KeyFactory.getInstance("RSA", this.provider).generatePublic(new RSAPublicKeySpec(instance.getModulus(), instance.getPublicExponent()));
            } catch (IOException e) {
                throw e;
            } catch (NoSuchProviderException e2) {
                throw new IOException("can't find provider " + this.provider);
            } catch (Exception e3) {
                throw new PEMException("problem extracting key: " + e3.toString(), e3);
            }
        }
    }

    private class X509AttributeCertificateParser implements PemObjectParser {
        private X509AttributeCertificateParser() {
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            return new X509V2AttributeCertificate(pemObject.getContent());
        }
    }

    private class X509CRLParser implements PemObjectParser {
        private String provider;

        public X509CRLParser(String str) {
            this.provider = str;
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                return CertificateFactory.getInstance("X.509", this.provider).generateCRL(new ByteArrayInputStream(pemObject.getContent()));
            } catch (Exception e) {
                throw new PEMException("problem parsing cert: " + e.toString(), e);
            }
        }
    }

    private class X509CertificateParser implements PemObjectParser {
        private String provider;

        public X509CertificateParser(String str) {
            this.provider = str;
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                return CertificateFactory.getInstance("X.509", this.provider).generateCertificate(new ByteArrayInputStream(pemObject.getContent()));
            } catch (Exception e) {
                throw new PEMException("problem parsing cert: " + e.toString(), e);
            }
        }
    }

    private class DSAKeyPairParser extends KeyPairParser {
        private String asymProvider;

        public DSAKeyPairParser(String str, String str2) {
            super(str);
            this.asymProvider = str2;
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                ASN1Sequence readKeyPair = readKeyPair(pemObject);
                if (readKeyPair.size() != 6) {
                    throw new PEMException("malformed sequence in DSA private key");
                }
                DERInteger dERInteger = (DERInteger) readKeyPair.getObjectAt(1);
                DERInteger dERInteger2 = (DERInteger) readKeyPair.getObjectAt(2);
                DERInteger dERInteger3 = (DERInteger) readKeyPair.getObjectAt(3);
                DERInteger dERInteger4 = (DERInteger) readKeyPair.getObjectAt(4);
                KeySpec dSAPrivateKeySpec = new DSAPrivateKeySpec(((DERInteger) readKeyPair.getObjectAt(5)).getValue(), dERInteger.getValue(), dERInteger2.getValue(), dERInteger3.getValue());
                KeySpec dSAPublicKeySpec = new DSAPublicKeySpec(dERInteger4.getValue(), dERInteger.getValue(), dERInteger2.getValue(), dERInteger3.getValue());
                KeyFactory instance = KeyFactory.getInstance("DSA", this.asymProvider);
                return new KeyPair(instance.generatePublic(dSAPublicKeySpec), instance.generatePrivate(dSAPrivateKeySpec));
            } catch (IOException e) {
                throw e;
            } catch (Exception e2) {
                throw new PEMException("problem creating DSA private key: " + e2.toString(), e2);
            }
        }
    }

    private class ECDSAKeyPairParser extends KeyPairParser {
        private String asymProvider;

        public ECDSAKeyPairParser(String str, String str2) {
            super(str);
            this.asymProvider = str2;
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                Object instance = ECPrivateKey.getInstance(readKeyPair(pemObject));
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, instance.getParameters());
                PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(algorithmIdentifier, instance);
                SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, instance.getPublicKey().getBytes());
                KeySpec pKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
                KeySpec x509EncodedKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
                KeyFactory instance2 = KeyFactory.getInstance("ECDSA", this.asymProvider);
                return new KeyPair(instance2.generatePublic(x509EncodedKeySpec), instance2.generatePrivate(pKCS8EncodedKeySpec));
            } catch (IOException e) {
                throw e;
            } catch (Exception e2) {
                throw new PEMException("problem creating EC private key: " + e2.toString(), e2);
            }
        }
    }

    private class RSAKeyPairParser extends KeyPairParser {
        private String asymProvider;

        public RSAKeyPairParser(String str, String str2) {
            super(str);
            this.asymProvider = str2;
        }

        public Object parseObject(PemObject pemObject) throws IOException {
            try {
                ASN1Sequence readKeyPair = readKeyPair(pemObject);
                if (readKeyPair.size() != 9) {
                    throw new PEMException("malformed sequence in RSA private key");
                }
                RSAPrivateKey instance = RSAPrivateKey.getInstance(readKeyPair);
                KeySpec rSAPublicKeySpec = new RSAPublicKeySpec(instance.getModulus(), instance.getPublicExponent());
                KeySpec rSAPrivateCrtKeySpec = new RSAPrivateCrtKeySpec(instance.getModulus(), instance.getPublicExponent(), instance.getPrivateExponent(), instance.getPrime1(), instance.getPrime2(), instance.getExponent1(), instance.getExponent2(), instance.getCoefficient());
                KeyFactory instance2 = KeyFactory.getInstance("RSA", this.asymProvider);
                return new KeyPair(instance2.generatePublic(rSAPublicKeySpec), instance2.generatePrivate(rSAPrivateCrtKeySpec));
            } catch (IOException e) {
                throw e;
            } catch (Exception e2) {
                throw new PEMException("problem creating RSA private key: " + e2.toString(), e2);
            }
        }
    }

    public PEMReader(Reader reader) {
        this(reader, null, BouncyCastleProvider.PROVIDER_NAME);
    }

    public PEMReader(Reader reader, PasswordFinder passwordFinder) {
        this(reader, passwordFinder, BouncyCastleProvider.PROVIDER_NAME);
    }

    public PEMReader(Reader reader, PasswordFinder passwordFinder, String str) {
        this(reader, passwordFinder, str, str);
    }

    public PEMReader(Reader reader, PasswordFinder passwordFinder, String str, String str2) {
        super(reader);
        this.parsers = new HashMap();
        this.pFinder = passwordFinder;
        this.parsers.put("CERTIFICATE REQUEST", new PKCS10CertificationRequestParser());
        this.parsers.put("NEW CERTIFICATE REQUEST", new PKCS10CertificationRequestParser());
        this.parsers.put("CERTIFICATE", new X509CertificateParser(str2));
        this.parsers.put("X509 CERTIFICATE", new X509CertificateParser(str2));
        this.parsers.put("X509 CRL", new X509CRLParser(str2));
        this.parsers.put("PKCS7", new PKCS7Parser());
        this.parsers.put("ATTRIBUTE CERTIFICATE", new X509AttributeCertificateParser());
        this.parsers.put("EC PARAMETERS", new ECNamedCurveSpecParser());
        this.parsers.put("PUBLIC KEY", new PublicKeyParser(str2));
        this.parsers.put("RSA PUBLIC KEY", new RSAPublicKeyParser(str2));
        this.parsers.put("RSA PRIVATE KEY", new RSAKeyPairParser(str, str2));
        this.parsers.put("DSA PRIVATE KEY", new DSAKeyPairParser(str, str2));
        this.parsers.put("EC PRIVATE KEY", new ECDSAKeyPairParser(str, str2));
        this.parsers.put("ENCRYPTED PRIVATE KEY", new EncryptedPrivateKeyParser(str, str2));
        this.parsers.put("PRIVATE KEY", new PrivateKeyParser(str2));
    }

    static byte[] crypt(boolean z, String str, byte[] bArr, char[] cArr, String str2, byte[] bArr2) throws IOException {
        Provider provider = null;
        if (str != null) {
            provider = Security.getProvider(str);
            if (provider == null) {
                throw new EncryptionException("cannot find provider: " + str);
            }
        }
        return crypt(z, provider, bArr, cArr, str2, bArr2);
    }

    static byte[] crypt(boolean z, Provider provider, byte[] bArr, char[] cArr, String str, byte[] bArr2) throws IOException {
        String str2;
        int i = 128;
        int i2 = 1;
        boolean z2 = false;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(bArr2);
        String str3 = "CBC";
        String str4 = "PKCS5Padding";
        if (str.endsWith("-CFB")) {
            str3 = "CFB";
            str4 = "NoPadding";
        }
        if (str.endsWith("-ECB") || "DES-EDE".equals(str) || "DES-EDE3".equals(str)) {
            str3 = "ECB";
            ivParameterSpec = null;
        }
        if (str.endsWith("-OFB")) {
            str3 = "OFB";
            str4 = "NoPadding";
        }
        String str5;
        SecretKey key;
        if (str.startsWith("DES-EDE")) {
            str5 = "DESede";
            if (!str.startsWith("DES-EDE3")) {
                z2 = true;
            }
            key = getKey(cArr, str5, 24, bArr2, z2);
            str2 = str5;
            AlgorithmParameterSpec algorithmParameterSpec = ivParameterSpec;
            Key key2 = key;
        } else if (str.startsWith("DES-")) {
            str5 = "DES";
            key = getKey(cArr, str5, 8, bArr2);
            str2 = str5;
            r5 = ivParameterSpec;
            r2 = key;
        } else if (str.startsWith("BF-")) {
            str5 = "Blowfish";
            key = getKey(cArr, str5, 16, bArr2);
            str2 = str5;
            r5 = ivParameterSpec;
            r2 = key;
        } else if (str.startsWith("RC2-")) {
            String str6 = "RC2";
            int i3 = str.startsWith("RC2-40-") ? 40 : str.startsWith("RC2-64-") ? 64 : 128;
            SecretKey key3 = getKey(cArr, str6, i3 / 8, bArr2);
            RC2ParameterSpec rC2ParameterSpec = ivParameterSpec == null ? new RC2ParameterSpec(i3) : new RC2ParameterSpec(i3, bArr2);
            str2 = str6;
            key = key3;
            r5 = rC2ParameterSpec;
            r2 = key;
        } else if (str.startsWith("AES-")) {
            String str7 = "AES";
            if (bArr2.length > 8) {
                Object obj = new byte[8];
                System.arraycopy(bArr2, 0, obj, 0, 8);
                bArr2 = obj;
            }
            if (!str.startsWith("AES-128-")) {
                if (str.startsWith("AES-192-")) {
                    i = 192;
                } else if (str.startsWith("AES-256-")) {
                    i = 256;
                } else {
                    throw new EncryptionException("unknown AES encryption with private key");
                }
            }
            SecretKey key4 = getKey(cArr, "AES", i / 8, bArr2);
            r5 = ivParameterSpec;
            r2 = key4;
            str2 = str7;
        } else {
            throw new EncryptionException("unknown encryption with private key");
        }
        try {
            Cipher instance = Cipher.getInstance(str2 + "/" + str3 + "/" + str4, provider);
            if (!z) {
                i2 = 2;
            }
            if (algorithmParameterSpec == null) {
                instance.init(i2, key2);
            } else {
                instance.init(i2, key2, algorithmParameterSpec);
            }
            return instance.doFinal(bArr);
        } catch (Throwable e) {
            throw new EncryptionException("exception using cipher - please check password and data.", e);
        }
    }

    public static SecretKey generateSecretKeyForPKCS5Scheme2(String str, char[] cArr, byte[] bArr, int i) {
        PBEParametersGenerator pKCS5S2ParametersGenerator = new PKCS5S2ParametersGenerator();
        pKCS5S2ParametersGenerator.init(PBEParametersGenerator.PKCS5PasswordToBytes(cArr), bArr, i);
        return new SecretKeySpec(((KeyParameter) pKCS5S2ParametersGenerator.generateDerivedParameters(PEMUtilities.getKeySize(str))).getKey(), str);
    }

    private static SecretKey getKey(char[] cArr, String str, int i, byte[] bArr) {
        return getKey(cArr, str, i, bArr, false);
    }

    private static SecretKey getKey(char[] cArr, String str, int i, byte[] bArr, boolean z) {
        OpenSSLPBEParametersGenerator openSSLPBEParametersGenerator = new OpenSSLPBEParametersGenerator();
        openSSLPBEParametersGenerator.init(PBEParametersGenerator.PKCS5PasswordToBytes(cArr), bArr);
        Object key = ((KeyParameter) openSSLPBEParametersGenerator.generateDerivedParameters(i * 8)).getKey();
        if (z && key.length >= 24) {
            System.arraycopy(key, 0, key, 16, 8);
        }
        return new SecretKeySpec(key, str);
    }

    public Object readObject() throws IOException {
        PemObject readPemObject = readPemObject();
        if (readPemObject == null) {
            return null;
        }
        String type = readPemObject.getType();
        if (this.parsers.containsKey(type)) {
            return ((PemObjectParser) this.parsers.get(type)).parseObject(readPemObject);
        }
        throw new IOException("unrecognised object: " + type);
    }
}
