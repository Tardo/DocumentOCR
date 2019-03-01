package org.bouncycastle.pkcs.jcajce;

import java.io.InputStream;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.JcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.operator.DefaultSecretKeyProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.SecretKeySizeProvider;
import org.bouncycastle.operator.jcajce.JceGenericKey;

public class JcePKCSPBEInputDecryptorProviderBuilder {
    private JcaJceHelper helper = new DefaultJcaJceHelper();
    private SecretKeySizeProvider keySizeProvider = DefaultSecretKeyProvider.INSTANCE;
    private boolean wrongPKCS12Zero = false;

    public InputDecryptorProvider build(final char[] cArr) {
        return new InputDecryptorProvider() {
            private Cipher cipher;
            private AlgorithmIdentifier encryptionAlg;
            private SecretKey key;

            /* renamed from: org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder$1$1 */
            class C02001 implements InputDecryptor {
                C02001() {
                }

                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return C02011.this.encryptionAlg;
                }

                public InputStream getInputStream(InputStream inputStream) {
                    return new CipherInputStream(inputStream, C02011.this.cipher);
                }

                public GenericKey getKey() {
                    return new JceGenericKey(C02011.this.encryptionAlg, C02011.this.key);
                }
            }

            public InputDecryptor get(AlgorithmIdentifier algorithmIdentifier) throws OperatorCreationException {
                ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
                try {
                    if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
                        PKCS12PBEParams instance = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());
                        KeySpec pBEKeySpec = new PBEKeySpec(cArr);
                        SecretKeyFactory createSecretKeyFactory = JcePKCSPBEInputDecryptorProviderBuilder.this.helper.createSecretKeyFactory(algorithm.getId());
                        AlgorithmParameterSpec pBEParameterSpec = new PBEParameterSpec(instance.getIV(), instance.getIterations().intValue());
                        this.key = createSecretKeyFactory.generateSecret(pBEKeySpec);
                        if (this.key instanceof BCPBEKey) {
                            ((BCPBEKey) this.key).setTryWrongPKCS12Zero(JcePKCSPBEInputDecryptorProviderBuilder.this.wrongPKCS12Zero);
                        }
                        this.cipher = JcePKCSPBEInputDecryptorProviderBuilder.this.helper.createCipher(algorithm.getId());
                        this.cipher.init(2, this.key, pBEParameterSpec);
                        this.encryptionAlg = algorithmIdentifier;
                    } else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2)) {
                        PBES2Parameters instance2 = PBES2Parameters.getInstance(algorithmIdentifier.getParameters());
                        PBKDF2Params instance3 = PBKDF2Params.getInstance(instance2.getKeyDerivationFunc().getParameters());
                        this.key = JcePKCSPBEInputDecryptorProviderBuilder.this.helper.createSecretKeyFactory(instance2.getKeyDerivationFunc().getAlgorithm().getId()).generateSecret(new PBEKeySpec(cArr, instance3.getSalt(), instance3.getIterationCount().intValue(), JcePKCSPBEInputDecryptorProviderBuilder.this.keySizeProvider.getKeySize(AlgorithmIdentifier.getInstance(instance2.getEncryptionScheme()))));
                        this.cipher = JcePKCSPBEInputDecryptorProviderBuilder.this.helper.createCipher(instance2.getEncryptionScheme().getAlgorithm().getId());
                        this.encryptionAlg = AlgorithmIdentifier.getInstance(instance2.getEncryptionScheme());
                        this.cipher.init(2, this.key, new IvParameterSpec(ASN1OctetString.getInstance(instance2.getEncryptionScheme().getParameters()).getOctets()));
                    }
                    return new C02001();
                } catch (Throwable e) {
                    throw new OperatorCreationException("unable to create InputDecryptor: " + e.getMessage(), e);
                }
            }
        };
    }

    public JcePKCSPBEInputDecryptorProviderBuilder setKeySizeProvider(SecretKeySizeProvider secretKeySizeProvider) {
        this.keySizeProvider = secretKeySizeProvider;
        return this;
    }

    public JcePKCSPBEInputDecryptorProviderBuilder setProvider(String str) {
        this.helper = new NamedJcaJceHelper(str);
        return this;
    }

    public JcePKCSPBEInputDecryptorProviderBuilder setProvider(Provider provider) {
        this.helper = new ProviderJcaJceHelper(provider);
        return this;
    }

    public JcePKCSPBEInputDecryptorProviderBuilder setTryWrongPKCS12Zero(boolean z) {
        this.wrongPKCS12Zero = z;
        return this;
    }
}
