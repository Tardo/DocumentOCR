package org.bouncycastle.cms;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;

public class CMSEnvelopedGenerator {
    public static final String AES128_CBC = NISTObjectIdentifiers.id_aes128_CBC.getId();
    public static final String AES128_WRAP = NISTObjectIdentifiers.id_aes128_wrap.getId();
    public static final String AES192_CBC = NISTObjectIdentifiers.id_aes192_CBC.getId();
    public static final String AES192_WRAP = NISTObjectIdentifiers.id_aes192_wrap.getId();
    public static final String AES256_CBC = NISTObjectIdentifiers.id_aes256_CBC.getId();
    public static final String AES256_WRAP = NISTObjectIdentifiers.id_aes256_wrap.getId();
    public static final String CAMELLIA128_CBC = NTTObjectIdentifiers.id_camellia128_cbc.getId();
    public static final String CAMELLIA128_WRAP = NTTObjectIdentifiers.id_camellia128_wrap.getId();
    public static final String CAMELLIA192_CBC = NTTObjectIdentifiers.id_camellia192_cbc.getId();
    public static final String CAMELLIA192_WRAP = NTTObjectIdentifiers.id_camellia192_wrap.getId();
    public static final String CAMELLIA256_CBC = NTTObjectIdentifiers.id_camellia256_cbc.getId();
    public static final String CAMELLIA256_WRAP = NTTObjectIdentifiers.id_camellia256_wrap.getId();
    public static final String CAST5_CBC = "1.2.840.113533.7.66.10";
    public static final String DES_EDE3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC.getId();
    public static final String DES_EDE3_WRAP = PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId();
    public static final String ECDH_SHA1KDF = X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.getId();
    public static final String ECMQV_SHA1KDF = X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme.getId();
    public static final String IDEA_CBC = "1.3.6.1.4.1.188.7.1.1.2";
    public static final String RC2_CBC = PKCSObjectIdentifiers.RC2_CBC.getId();
    public static final String SEED_CBC = KISAObjectIdentifiers.id_seedCBC.getId();
    public static final String SEED_WRAP = KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId();
    final List oldRecipientInfoGenerators;
    protected OriginatorInfo originatorInfo;
    final SecureRandom rand;
    final List recipientInfoGenerators;
    protected CMSAttributeTableGenerator unprotectedAttributeGenerator;

    public CMSEnvelopedGenerator() {
        this(new SecureRandom());
    }

    public CMSEnvelopedGenerator(SecureRandom secureRandom) {
        this.oldRecipientInfoGenerators = new ArrayList();
        this.recipientInfoGenerators = new ArrayList();
        this.unprotectedAttributeGenerator = null;
        this.rand = secureRandom;
    }

    public void addKEKRecipient(SecretKey secretKey, KEKIdentifier kEKIdentifier) {
        this.oldRecipientInfoGenerators.add(new JceKEKRecipientInfoGenerator(kEKIdentifier, secretKey));
    }

    public void addKEKRecipient(SecretKey secretKey, byte[] bArr) {
        addKEKRecipient(secretKey, new KEKIdentifier(bArr, null, null));
    }

    public void addKeyAgreementRecipient(String str, PrivateKey privateKey, PublicKey publicKey, X509Certificate x509Certificate, String str2, String str3) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        addKeyAgreementRecipient(str, privateKey, publicKey, x509Certificate, str2, CMSUtils.getProvider(str3));
    }

    public void addKeyAgreementRecipient(String str, PrivateKey privateKey, PublicKey publicKey, X509Certificate x509Certificate, String str2, Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        Collection arrayList = new ArrayList();
        arrayList.add(x509Certificate);
        addKeyAgreementRecipients(str, privateKey, publicKey, arrayList, str2, provider);
    }

    public void addKeyAgreementRecipients(String str, PrivateKey privateKey, PublicKey publicKey, Collection collection, String str2, String str3) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        addKeyAgreementRecipients(str, privateKey, publicKey, collection, str2, CMSUtils.getProvider(str3));
    }

    public void addKeyAgreementRecipients(String str, PrivateKey privateKey, PublicKey publicKey, Collection collection, String str2, Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        JceKeyAgreeRecipientInfoGenerator provider2 = new JceKeyAgreeRecipientInfoGenerator(new ASN1ObjectIdentifier(str), privateKey, publicKey, new ASN1ObjectIdentifier(str2)).setProvider(provider);
        for (X509Certificate addRecipient : collection) {
            try {
                provider2.addRecipient(addRecipient);
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("unable to encode certificate: " + e.getMessage());
            }
        }
        this.oldRecipientInfoGenerators.add(provider2);
    }

    public void addKeyTransRecipient(PublicKey publicKey, byte[] bArr) throws IllegalArgumentException {
        this.oldRecipientInfoGenerators.add(new JceKeyTransRecipientInfoGenerator(bArr, publicKey));
    }

    public void addKeyTransRecipient(X509Certificate x509Certificate) throws IllegalArgumentException {
        try {
            this.oldRecipientInfoGenerators.add(new JceKeyTransRecipientInfoGenerator(x509Certificate));
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("unable to encode certificate: " + e.getMessage());
        }
    }

    public void addPasswordRecipient(CMSPBEKey cMSPBEKey, String str) {
        this.oldRecipientInfoGenerators.add(new JcePasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(str), cMSPBEKey.getPassword()).setSaltAndIterationCount(cMSPBEKey.getSalt(), cMSPBEKey.getIterationCount()).setPasswordConversionScheme(cMSPBEKey instanceof PKCS5Scheme2UTF8PBEKey ? 1 : 0));
    }

    public void addRecipientInfoGenerator(RecipientInfoGenerator recipientInfoGenerator) {
        this.recipientInfoGenerators.add(recipientInfoGenerator);
    }

    protected void convertOldRecipients(SecureRandom secureRandom, Provider provider) {
        for (Object next : this.oldRecipientInfoGenerators) {
            if (next instanceof JceKeyTransRecipientInfoGenerator) {
                JceKeyTransRecipientInfoGenerator jceKeyTransRecipientInfoGenerator = (JceKeyTransRecipientInfoGenerator) next;
                if (provider != null) {
                    jceKeyTransRecipientInfoGenerator.setProvider(provider);
                }
                this.recipientInfoGenerators.add(jceKeyTransRecipientInfoGenerator);
            } else if (next instanceof KEKRecipientInfoGenerator) {
                JceKEKRecipientInfoGenerator jceKEKRecipientInfoGenerator = (JceKEKRecipientInfoGenerator) next;
                if (provider != null) {
                    jceKEKRecipientInfoGenerator.setProvider(provider);
                }
                jceKEKRecipientInfoGenerator.setSecureRandom(secureRandom);
                this.recipientInfoGenerators.add(jceKEKRecipientInfoGenerator);
            } else if (next instanceof JcePasswordRecipientInfoGenerator) {
                JcePasswordRecipientInfoGenerator jcePasswordRecipientInfoGenerator = (JcePasswordRecipientInfoGenerator) next;
                if (provider != null) {
                    jcePasswordRecipientInfoGenerator.setProvider(provider);
                }
                jcePasswordRecipientInfoGenerator.setSecureRandom(secureRandom);
                this.recipientInfoGenerators.add(jcePasswordRecipientInfoGenerator);
            } else if (next instanceof JceKeyAgreeRecipientInfoGenerator) {
                JceKeyAgreeRecipientInfoGenerator jceKeyAgreeRecipientInfoGenerator = (JceKeyAgreeRecipientInfoGenerator) next;
                if (provider != null) {
                    jceKeyAgreeRecipientInfoGenerator.setProvider(provider);
                }
                jceKeyAgreeRecipientInfoGenerator.setSecureRandom(secureRandom);
                this.recipientInfoGenerators.add(jceKeyAgreeRecipientInfoGenerator);
            }
        }
        this.oldRecipientInfoGenerators.clear();
    }

    protected AlgorithmIdentifier getAlgorithmIdentifier(String str, AlgorithmParameters algorithmParameters) throws IOException {
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(str), algorithmParameters != null ? ASN1Primitive.fromByteArray(algorithmParameters.getEncoded("ASN.1")) : DERNull.INSTANCE);
    }

    public void setOriginatorInfo(OriginatorInformation originatorInformation) {
        this.originatorInfo = originatorInformation.toASN1Structure();
    }

    public void setUnprotectedAttributeGenerator(CMSAttributeTableGenerator cMSAttributeTableGenerator) {
        this.unprotectedAttributeGenerator = cMSAttributeTableGenerator;
    }
}
