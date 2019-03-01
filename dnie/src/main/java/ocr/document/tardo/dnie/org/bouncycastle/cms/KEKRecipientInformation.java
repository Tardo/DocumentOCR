package org.bouncycastle.cms;

import java.io.IOException;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.Provider;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.jcajce.JceKEKAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;

public class KEKRecipientInformation extends RecipientInformation {
    private KEKRecipientInfo info;

    KEKRecipientInformation(KEKRecipientInfo kEKRecipientInfo, AlgorithmIdentifier algorithmIdentifier, CMSSecureReadable cMSSecureReadable, AuthAttributesProvider authAttributesProvider) {
        super(kEKRecipientInfo.getKeyEncryptionAlgorithm(), algorithmIdentifier, cMSSecureReadable, authAttributesProvider);
        this.info = kEKRecipientInfo;
        this.rid = new KEKRecipientId(kEKRecipientInfo.getKekid().getKeyIdentifier().getOctets());
    }

    public CMSTypedStream getContentStream(Key key, String str) throws CMSException, NoSuchProviderException {
        return getContentStream(key, CMSUtils.getProvider(str));
    }

    public CMSTypedStream getContentStream(Key key, Provider provider) throws CMSException {
        try {
            Recipient jceKEKEnvelopedRecipient = this.secureReadable instanceof CMSEnvelopedSecureReadable ? new JceKEKEnvelopedRecipient((SecretKey) key) : new JceKEKAuthenticatedRecipient((SecretKey) key);
            if (provider != null) {
                jceKEKEnvelopedRecipient.setProvider(provider);
            }
            return getContentStream(jceKEKEnvelopedRecipient);
        } catch (Exception e) {
            throw new CMSException("encoding error: " + e.getMessage(), e);
        }
    }

    protected RecipientOperator getRecipientOperator(Recipient recipient) throws CMSException, IOException {
        return ((KEKRecipient) recipient).getRecipientOperator(this.keyEncAlg, this.messageAlgorithm, this.info.getEncryptedKey().getOctets());
    }
}
