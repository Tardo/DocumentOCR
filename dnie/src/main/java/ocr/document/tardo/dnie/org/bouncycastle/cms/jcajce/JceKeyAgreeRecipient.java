package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ecc.MQVuserKeyingMaterial;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSEnvelopedGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyAgreeRecipient;
import org.bouncycastle.jce.spec.MQVPrivateKeySpec;
import org.bouncycastle.jce.spec.MQVPublicKeySpec;

public abstract class JceKeyAgreeRecipient implements KeyAgreeRecipient {
    protected EnvelopedDataHelper contentHelper = this.helper;
    protected EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    private PrivateKey recipientKey;

    public JceKeyAgreeRecipient(PrivateKey privateKey) {
        this.recipientKey = privateKey;
    }

    private SecretKey calculateAgreedWrapKey(AlgorithmIdentifier algorithmIdentifier, ASN1ObjectIdentifier aSN1ObjectIdentifier, PublicKey publicKey, ASN1OctetString aSN1OctetString, PrivateKey privateKey) throws CMSException, GeneralSecurityException, IOException {
        Key mQVPrivateKeySpec;
        Key key;
        if (algorithmIdentifier.getAlgorithm().getId().equals(CMSEnvelopedGenerator.ECMQV_SHA1KDF)) {
            MQVPublicKeySpec mQVPublicKeySpec = new MQVPublicKeySpec(publicKey, this.helper.createKeyFactory(algorithmIdentifier.getAlgorithm()).generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(getPrivateKeyAlgorithmIdentifier(), MQVuserKeyingMaterial.getInstance(ASN1Primitive.fromByteArray(aSN1OctetString.getOctets())).getEphemeralPublicKey().getPublicKey().getBytes()).getEncoded())));
            mQVPrivateKeySpec = new MQVPrivateKeySpec(privateKey, privateKey);
            key = mQVPublicKeySpec;
        }
        KeyAgreement createKeyAgreement = this.helper.createKeyAgreement(algorithmIdentifier.getAlgorithm());
        createKeyAgreement.init(mQVPrivateKeySpec);
        createKeyAgreement.doPhase(key, true);
        return createKeyAgreement.generateSecret(aSN1ObjectIdentifier.getId());
    }

    private Key unwrapSessionKey(ASN1ObjectIdentifier aSN1ObjectIdentifier, SecretKey secretKey, ASN1ObjectIdentifier aSN1ObjectIdentifier2, byte[] bArr) throws CMSException, InvalidKeyException, NoSuchAlgorithmException {
        Cipher createCipher = this.helper.createCipher(aSN1ObjectIdentifier);
        createCipher.init(4, secretKey);
        return createCipher.unwrap(bArr, this.helper.getBaseCipherName(aSN1ObjectIdentifier2), 3);
    }

    protected Key extractSecretKey(AlgorithmIdentifier algorithmIdentifier, AlgorithmIdentifier algorithmIdentifier2, SubjectPublicKeyInfo subjectPublicKeyInfo, ASN1OctetString aSN1OctetString, byte[] bArr) throws CMSException {
        try {
            ASN1ObjectIdentifier algorithm = AlgorithmIdentifier.getInstance(algorithmIdentifier.getParameters()).getAlgorithm();
            return unwrapSessionKey(algorithm, calculateAgreedWrapKey(algorithmIdentifier, algorithm, this.helper.createKeyFactory(algorithmIdentifier.getAlgorithm()).generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded())), aSN1OctetString, this.recipientKey), algorithmIdentifier2.getAlgorithm(), bArr);
        } catch (Exception e) {
            throw new CMSException("can't find algorithm.", e);
        } catch (Exception e2) {
            throw new CMSException("key invalid in message.", e2);
        } catch (Exception e22) {
            throw new CMSException("originator key spec invalid.", e22);
        } catch (Exception e222) {
            throw new CMSException("required padding not supported.", e222);
        } catch (Exception e2222) {
            throw new CMSException("originator key invalid.", e2222);
        }
    }

    public AlgorithmIdentifier getPrivateKeyAlgorithmIdentifier() {
        return PrivateKeyInfo.getInstance(this.recipientKey.getEncoded()).getPrivateKeyAlgorithm();
    }

    public JceKeyAgreeRecipient setContentProvider(String str) {
        this.contentHelper = CMSUtils.createContentHelper(str);
        return this;
    }

    public JceKeyAgreeRecipient setContentProvider(Provider provider) {
        this.contentHelper = CMSUtils.createContentHelper(provider);
        return this;
    }

    public JceKeyAgreeRecipient setProvider(String str) {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(str));
        this.contentHelper = this.helper;
        return this;
    }

    public JceKeyAgreeRecipient setProvider(Provider provider) {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
        this.contentHelper = this.helper;
        return this;
    }
}
