package org.bouncycastle.openssl;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

public class PKCS8Generator implements PemObjectGenerator {
    public static final ASN1ObjectIdentifier AES_128_CBC = NISTObjectIdentifiers.id_aes128_CBC;
    public static final ASN1ObjectIdentifier AES_192_CBC = NISTObjectIdentifiers.id_aes192_CBC;
    public static final ASN1ObjectIdentifier AES_256_CBC = NISTObjectIdentifiers.id_aes256_CBC;
    public static final ASN1ObjectIdentifier DES3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC;
    public static final ASN1ObjectIdentifier PBE_SHA1_2DES = PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC;
    public static final ASN1ObjectIdentifier PBE_SHA1_3DES = PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC;
    public static final ASN1ObjectIdentifier PBE_SHA1_RC2_128 = PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC;
    public static final ASN1ObjectIdentifier PBE_SHA1_RC2_40 = PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC;
    public static final ASN1ObjectIdentifier PBE_SHA1_RC4_128 = PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4;
    public static final ASN1ObjectIdentifier PBE_SHA1_RC4_40 = PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4;
    private JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder;
    private PrivateKeyInfo key;
    private OutputEncryptor outputEncryptor;

    public PKCS8Generator(PrivateKey privateKey) {
        this.key = PrivateKeyInfo.getInstance(privateKey.getEncoded());
    }

    public PKCS8Generator(PrivateKey privateKey, ASN1ObjectIdentifier aSN1ObjectIdentifier, String str) throws NoSuchProviderException, NoSuchAlgorithmException {
        Provider provider = Security.getProvider(str);
        if (provider == null) {
            throw new NoSuchProviderException("cannot find provider: " + str);
        }
        init(privateKey, aSN1ObjectIdentifier, provider);
    }

    public PKCS8Generator(PrivateKey privateKey, ASN1ObjectIdentifier aSN1ObjectIdentifier, Provider provider) throws NoSuchAlgorithmException {
        init(privateKey, aSN1ObjectIdentifier, provider);
    }

    public PKCS8Generator(PrivateKeyInfo privateKeyInfo, OutputEncryptor outputEncryptor) {
        this.key = privateKeyInfo;
        this.outputEncryptor = outputEncryptor;
    }

    private PemObject generate(PrivateKeyInfo privateKeyInfo, OutputEncryptor outputEncryptor) throws PemGenerationException {
        try {
            byte[] encoded = privateKeyInfo.getEncoded();
            if (outputEncryptor == null) {
                return new PemObject("PRIVATE KEY", encoded);
            }
            OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            OutputStream outputStream = outputEncryptor.getOutputStream(byteArrayOutputStream);
            outputStream.write(privateKeyInfo.getEncoded());
            outputStream.close();
            return new PemObject("ENCRYPTED PRIVATE KEY", new EncryptedPrivateKeyInfo(outputEncryptor.getAlgorithmIdentifier(), byteArrayOutputStream.toByteArray()).getEncoded());
        } catch (Throwable e) {
            throw new PemGenerationException("unable to process encoded key data: " + e.getMessage(), e);
        }
    }

    private void init(PrivateKey privateKey, ASN1ObjectIdentifier aSN1ObjectIdentifier, Provider provider) throws NoSuchAlgorithmException {
        this.key = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        this.encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(aSN1ObjectIdentifier);
        this.encryptorBuilder.setProvider(provider);
    }

    public PemObject generate() throws PemGenerationException {
        try {
            if (this.encryptorBuilder != null) {
                this.outputEncryptor = this.encryptorBuilder.build();
            }
            return this.outputEncryptor != null ? generate(this.key, this.outputEncryptor) : generate(this.key, null);
        } catch (Throwable e) {
            throw new PemGenerationException("unable to create operator: " + e.getMessage(), e);
        }
    }

    public PKCS8Generator setIterationCount(int i) {
        this.encryptorBuilder.setIterationCount(i);
        return this;
    }

    public PKCS8Generator setPassword(char[] cArr) {
        this.encryptorBuilder.setPasssword(cArr);
        return this;
    }

    public PKCS8Generator setSecureRandom(SecureRandom secureRandom) {
        this.encryptorBuilder.setRandom(secureRandom);
        return this;
    }
}
