package org.bouncycastle.pkcs.jcajce;

import java.io.OutputStream;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.JcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.operator.DefaultSecretKeyProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.SecretKeySizeProvider;

public class JcePKCSPBEOutputEncryptorBuilder {
    private ASN1ObjectIdentifier algorithm;
    private JcaJceHelper helper = new DefaultJcaJceHelper();
    private ASN1ObjectIdentifier keyEncAlgorithm;
    private SecretKeySizeProvider keySizeProvider = DefaultSecretKeyProvider.INSTANCE;
    private SecureRandom random;

    public JcePKCSPBEOutputEncryptorBuilder(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        if (isPKCS12(aSN1ObjectIdentifier)) {
            this.algorithm = aSN1ObjectIdentifier;
            this.keyEncAlgorithm = aSN1ObjectIdentifier;
            return;
        }
        this.algorithm = PKCSObjectIdentifiers.id_PBES2;
        this.keyEncAlgorithm = aSN1ObjectIdentifier;
    }

    private boolean isPKCS12(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return aSN1ObjectIdentifier.on(PKCSObjectIdentifiers.pkcs_12PbeIds) || aSN1ObjectIdentifier.on(BCObjectIdentifiers.bc_pbe_sha1_pkcs12) || aSN1ObjectIdentifier.on(BCObjectIdentifiers.bc_pbe_sha256_pkcs12);
    }

    public OutputEncryptor build(final char[] cArr) throws OperatorCreationException {
        if (this.random == null) {
            this.random = new SecureRandom();
        }
        byte[] bArr = new byte[20];
        this.random.nextBytes(bArr);
        try {
            Cipher createCipher;
            AlgorithmIdentifier algorithmIdentifier;
            Key generateSecret;
            if (this.algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
                KeySpec pBEKeySpec = new PBEKeySpec(cArr);
                SecretKeyFactory createSecretKeyFactory = this.helper.createSecretKeyFactory(this.algorithm.getId());
                AlgorithmParameterSpec pBEParameterSpec = new PBEParameterSpec(bArr, 1024);
                generateSecret = createSecretKeyFactory.generateSecret(pBEKeySpec);
                createCipher = this.helper.createCipher(this.algorithm.getId());
                createCipher.init(1, generateSecret, pBEParameterSpec);
                algorithmIdentifier = new AlgorithmIdentifier(this.algorithm, new PKCS12PBEParams(bArr, 1024));
            } else if (this.algorithm.equals(PKCSObjectIdentifiers.id_PBES2)) {
                generateSecret = this.helper.createSecretKeyFactory(PKCSObjectIdentifiers.id_PBKDF2.getId()).generateSecret(new PBEKeySpec(cArr, bArr, 1024, this.keySizeProvider.getKeySize(new AlgorithmIdentifier(this.keyEncAlgorithm))));
                createCipher = this.helper.createCipher(this.keyEncAlgorithm.getId());
                createCipher.init(1, generateSecret, this.random);
                algorithmIdentifier = new AlgorithmIdentifier(this.algorithm, new PBES2Parameters(new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(bArr, 1024)), new EncryptionScheme(this.keyEncAlgorithm, ASN1Primitive.fromByteArray(createCipher.getParameters().getEncoded()))));
            } else {
                throw new OperatorCreationException("unrecognised algorithm");
            }
            return new OutputEncryptor() {
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return algorithmIdentifier;
                }

                public GenericKey getKey() {
                    return JcePKCSPBEOutputEncryptorBuilder.this.isPKCS12(algorithmIdentifier.getAlgorithm()) ? new GenericKey(algorithmIdentifier, PBEParametersGenerator.PKCS5PasswordToBytes(cArr)) : new GenericKey(algorithmIdentifier, PBEParametersGenerator.PKCS12PasswordToBytes(cArr));
                }

                public OutputStream getOutputStream(OutputStream outputStream) {
                    return new CipherOutputStream(outputStream, createCipher);
                }
            };
        } catch (Throwable e) {
            throw new OperatorCreationException("unable to create OutputEncryptor: " + e.getMessage(), e);
        }
    }

    public JcePKCSPBEOutputEncryptorBuilder setKeySizeProvider(SecretKeySizeProvider secretKeySizeProvider) {
        this.keySizeProvider = secretKeySizeProvider;
        return this;
    }

    public JcePKCSPBEOutputEncryptorBuilder setProvider(String str) {
        this.helper = new NamedJcaJceHelper(str);
        return this;
    }

    public JcePKCSPBEOutputEncryptorBuilder setProvider(Provider provider) {
        this.helper = new ProviderJcaJceHelper(provider);
        return this;
    }
}
