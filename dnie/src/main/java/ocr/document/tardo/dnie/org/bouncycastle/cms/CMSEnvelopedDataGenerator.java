package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.HashMap;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputEncryptor;

public class CMSEnvelopedDataGenerator extends CMSEnvelopedGenerator {
    public CMSEnvelopedDataGenerator(SecureRandom secureRandom) {
        super(secureRandom);
    }

    private CMSEnvelopedData doGenerate(CMSTypedData cMSTypedData, OutputEncryptor outputEncryptor) throws CMSException {
        if (this.oldRecipientInfoGenerators.isEmpty()) {
            ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
            OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            try {
                OutputStream outputStream = outputEncryptor.getOutputStream(byteArrayOutputStream);
                cMSTypedData.write(outputStream);
                outputStream.close();
                byte[] toByteArray = byteArrayOutputStream.toByteArray();
                AlgorithmIdentifier algorithmIdentifier = outputEncryptor.getAlgorithmIdentifier();
                ASN1OctetString bEROctetString = new BEROctetString(toByteArray);
                GenericKey key = outputEncryptor.getKey();
                for (RecipientInfoGenerator generate : this.recipientInfoGenerators) {
                    aSN1EncodableVector.add(generate.generate(key));
                }
                EncryptedContentInfo encryptedContentInfo = new EncryptedContentInfo(cMSTypedData.getContentType(), algorithmIdentifier, bEROctetString);
                ASN1Set aSN1Set = null;
                if (this.unprotectedAttributeGenerator != null) {
                    aSN1Set = new BERSet(this.unprotectedAttributeGenerator.getAttributes(new HashMap()).toASN1EncodableVector());
                }
                return new CMSEnvelopedData(new ContentInfo(CMSObjectIdentifiers.envelopedData, new EnvelopedData(this.originatorInfo, new DERSet(aSN1EncodableVector), encryptedContentInfo, aSN1Set)));
            } catch (IOException e) {
                throw new CMSException("");
            }
        }
        throw new IllegalStateException("can only use addRecipientGenerator() with this method");
    }

    private CMSEnvelopedData generate(final CMSProcessable cMSProcessable, String str, int i, Provider provider, Provider provider2) throws NoSuchAlgorithmException, CMSException {
        convertOldRecipients(this.rand, provider2);
        JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = i != -1 ? new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(str), i) : new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(str));
        jceCMSContentEncryptorBuilder.setProvider(provider);
        jceCMSContentEncryptorBuilder.setSecureRandom(this.rand);
        return doGenerate(new CMSTypedData() {
            public Object getContent() {
                return cMSProcessable;
            }

            public ASN1ObjectIdentifier getContentType() {
                return CMSObjectIdentifiers.data;
            }

            public void write(OutputStream outputStream) throws IOException, CMSException {
                cMSProcessable.write(outputStream);
            }
        }, jceCMSContentEncryptorBuilder.build());
    }

    public CMSEnvelopedData generate(CMSProcessable cMSProcessable, String str, int i, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return generate(cMSProcessable, str, i, CMSUtils.getProvider(str2));
    }

    public CMSEnvelopedData generate(CMSProcessable cMSProcessable, String str, int i, Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return generate(cMSProcessable, str, i, CMSEnvelopedHelper.INSTANCE.createSymmetricKeyGenerator(str, provider).getProvider(), provider);
    }

    public CMSEnvelopedData generate(CMSProcessable cMSProcessable, String str, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return generate(cMSProcessable, str, CMSUtils.getProvider(str2));
    }

    public CMSEnvelopedData generate(CMSProcessable cMSProcessable, String str, Provider provider) throws NoSuchAlgorithmException, CMSException {
        return generate(cMSProcessable, str, -1, CMSEnvelopedHelper.INSTANCE.createSymmetricKeyGenerator(str, provider).getProvider(), provider);
    }

    public CMSEnvelopedData generate(CMSTypedData cMSTypedData, OutputEncryptor outputEncryptor) throws CMSException {
        return doGenerate(cMSTypedData, outputEncryptor);
    }
}
