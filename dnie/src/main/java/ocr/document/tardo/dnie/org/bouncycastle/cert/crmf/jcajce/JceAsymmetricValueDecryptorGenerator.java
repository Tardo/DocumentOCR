package org.bouncycastle.cert.crmf.jcajce;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.ValueDecryptorGenerator;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.operator.InputDecryptor;

public class JceAsymmetricValueDecryptorGenerator implements ValueDecryptorGenerator {
    private CRMFHelper helper = new CRMFHelper(new DefaultJcaJceHelper());
    private PrivateKey recipientKey;

    public JceAsymmetricValueDecryptorGenerator(PrivateKey privateKey) {
        this.recipientKey = privateKey;
    }

    private Key extractSecretKey(AlgorithmIdentifier algorithmIdentifier, AlgorithmIdentifier algorithmIdentifier2, byte[] bArr) throws CRMFException {
        Key key = null;
        try {
            Cipher createCipher = this.helper.createCipher(algorithmIdentifier.getAlgorithm());
            try {
                createCipher.init(4, this.recipientKey);
                key = createCipher.unwrap(bArr, algorithmIdentifier2.getAlgorithm().getId(), 3);
            } catch (GeneralSecurityException e) {
            } catch (IllegalStateException e2) {
            } catch (UnsupportedOperationException e3) {
            } catch (ProviderException e4) {
            }
            if (key != null) {
                return key;
            }
            createCipher.init(2, this.recipientKey);
            return new SecretKeySpec(createCipher.doFinal(bArr), algorithmIdentifier2.getAlgorithm().getId());
        } catch (Throwable e5) {
            throw new CRMFException("key invalid in message.", e5);
        } catch (Throwable e52) {
            throw new CRMFException("illegal blocksize in message.", e52);
        } catch (Throwable e522) {
            throw new CRMFException("bad padding in message.", e522);
        }
    }

    public InputDecryptor getValueDecryptor(AlgorithmIdentifier algorithmIdentifier, final AlgorithmIdentifier algorithmIdentifier2, byte[] bArr) throws CRMFException {
        final Cipher createContentCipher = this.helper.createContentCipher(extractSecretKey(algorithmIdentifier, algorithmIdentifier2, bArr), algorithmIdentifier2);
        return new InputDecryptor() {
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return algorithmIdentifier2;
            }

            public InputStream getInputStream(InputStream inputStream) {
                return new CipherInputStream(inputStream, createContentCipher);
            }
        };
    }

    public JceAsymmetricValueDecryptorGenerator setProvider(String str) {
        this.helper = new CRMFHelper(new NamedJcaJceHelper(str));
        return this;
    }

    public JceAsymmetricValueDecryptorGenerator setProvider(Provider provider) {
        this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));
        return this;
    }
}
