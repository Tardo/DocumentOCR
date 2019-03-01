package org.bouncycastle.openssl.jcajce;

import java.io.OutputStream;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.JcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JceGenericKey;

public class JceOpenSSLPKCS8EncryptorBuilder {
    public static final String AES_128_CBC = NISTObjectIdentifiers.id_aes128_CBC.getId();
    public static final String AES_192_CBC = NISTObjectIdentifiers.id_aes192_CBC.getId();
    public static final String AES_256_CBC = NISTObjectIdentifiers.id_aes256_CBC.getId();
    public static final String DES3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC.getId();
    public static final String PBE_SHA1_2DES = PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC.getId();
    public static final String PBE_SHA1_3DES = PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC.getId();
    public static final String PBE_SHA1_RC2_128 = PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC.getId();
    public static final String PBE_SHA1_RC2_40 = PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC.getId();
    public static final String PBE_SHA1_RC4_128 = PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4.getId();
    public static final String PBE_SHA1_RC4_40 = PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4.getId();
    private ASN1ObjectIdentifier algOID;
    private Cipher cipher;
    private JcaJceHelper helper = new DefaultJcaJceHelper();
    int iterationCount;
    private SecretKey key;
    private AlgorithmParameterGenerator paramGen;
    private AlgorithmParameters params;
    private char[] password;
    private SecureRandom random;
    byte[] salt;
    private SecretKeyFactory secKeyFact;

    public JceOpenSSLPKCS8EncryptorBuilder(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        this.algOID = aSN1ObjectIdentifier;
        this.iterationCount = 2048;
    }

    public OutputEncryptor build() throws OperatorCreationException {
        this.salt = new byte[20];
        if (this.random == null) {
            this.random = new SecureRandom();
        }
        this.random.nextBytes(this.salt);
        try {
            AlgorithmIdentifier algorithmIdentifier;
            this.cipher = this.helper.createCipher(this.algOID.getId());
            if (PEMUtilities.isPKCS5Scheme2(this.algOID)) {
                this.paramGen = this.helper.createAlgorithmParameterGenerator(this.algOID.getId());
            } else {
                this.secKeyFact = this.helper.createSecretKeyFactory(this.algOID.getId());
            }
            if (PEMUtilities.isPKCS5Scheme2(this.algOID)) {
                this.params = this.paramGen.generateParameters();
                try {
                    ASN1Encodable keyDerivationFunc = new KeyDerivationFunc(this.algOID, ASN1Primitive.fromByteArray(this.params.getEncoded()));
                    ASN1Encodable keyDerivationFunc2 = new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(this.salt, this.iterationCount));
                    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
                    aSN1EncodableVector.add(keyDerivationFunc2);
                    aSN1EncodableVector.add(keyDerivationFunc);
                    algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, PBES2Parameters.getInstance(new DERSequence(aSN1EncodableVector)));
                    this.key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(this.algOID.getId(), this.password, this.salt, this.iterationCount);
                    try {
                        this.cipher.init(1, this.key, this.params);
                    } catch (Throwable e) {
                        throw new OperatorCreationException(e.getMessage(), e);
                    }
                } catch (Throwable e2) {
                    throw new OperatorCreationException(e2.getMessage(), e2);
                }
            } else if (PEMUtilities.isPKCS12(this.algOID)) {
                ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
                aSN1EncodableVector2.add(new DEROctetString(this.salt));
                aSN1EncodableVector2.add(new ASN1Integer((long) this.iterationCount));
                algorithmIdentifier = new AlgorithmIdentifier(this.algOID, PKCS12PBEParams.getInstance(new DERSequence(aSN1EncodableVector2)));
                try {
                    KeySpec pBEKeySpec = new PBEKeySpec(this.password);
                    AlgorithmParameterSpec pBEParameterSpec = new PBEParameterSpec(this.salt, this.iterationCount);
                    this.key = this.secKeyFact.generateSecret(pBEKeySpec);
                    this.cipher.init(1, this.key, pBEParameterSpec);
                } catch (Throwable e22) {
                    throw new OperatorCreationException(e22.getMessage(), e22);
                }
            } else {
                throw new OperatorCreationException("unknown algorithm: " + this.algOID, null);
            }
            return new OutputEncryptor() {
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return algorithmIdentifier;
                }

                public GenericKey getKey() {
                    return new JceGenericKey(algorithmIdentifier, JceOpenSSLPKCS8EncryptorBuilder.this.key);
                }

                public OutputStream getOutputStream(OutputStream outputStream) {
                    return new CipherOutputStream(outputStream, JceOpenSSLPKCS8EncryptorBuilder.this.cipher);
                }
            };
        } catch (Throwable e222) {
            throw new OperatorCreationException(this.algOID + " not available: " + e222.getMessage(), e222);
        }
    }

    public JceOpenSSLPKCS8EncryptorBuilder setIterationCount(int i) {
        this.iterationCount = i;
        return this;
    }

    public JceOpenSSLPKCS8EncryptorBuilder setPasssword(char[] cArr) {
        this.password = cArr;
        return this;
    }

    public JceOpenSSLPKCS8EncryptorBuilder setProvider(String str) {
        this.helper = new NamedJcaJceHelper(str);
        return this;
    }

    public JceOpenSSLPKCS8EncryptorBuilder setProvider(Provider provider) {
        this.helper = new ProviderJcaJceHelper(provider);
        return this;
    }

    public JceOpenSSLPKCS8EncryptorBuilder setRandom(SecureRandom secureRandom) {
        this.random = secureRandom;
        return this;
    }
}
