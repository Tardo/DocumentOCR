package org.bouncycastle.cms.jcajce;

import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipient;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyUnwrapper;

public abstract class JceKeyTransRecipient implements KeyTransRecipient {
    protected EnvelopedDataHelper contentHelper = this.helper;
    protected Map extraMappings = new HashMap();
    protected EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    private PrivateKey recipientKey;

    public JceKeyTransRecipient(PrivateKey privateKey) {
        this.recipientKey = privateKey;
    }

    protected Key extractSecretKey(AlgorithmIdentifier algorithmIdentifier, AlgorithmIdentifier algorithmIdentifier2, byte[] bArr) throws CMSException {
        JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper = this.helper.createAsymmetricUnwrapper(algorithmIdentifier, this.recipientKey);
        if (!this.extraMappings.isEmpty()) {
            for (ASN1ObjectIdentifier aSN1ObjectIdentifier : this.extraMappings.keySet()) {
                createAsymmetricUnwrapper.setAlgorithmMapping(aSN1ObjectIdentifier, (String) this.extraMappings.get(aSN1ObjectIdentifier));
            }
        }
        try {
            return this.helper.getJceKey(algorithmIdentifier2.getAlgorithm(), createAsymmetricUnwrapper.generateUnwrappedKey(algorithmIdentifier2, bArr));
        } catch (Exception e) {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
    }

    public JceKeyTransRecipient setAlgorithmMapping(ASN1ObjectIdentifier aSN1ObjectIdentifier, String str) {
        this.extraMappings.put(aSN1ObjectIdentifier, str);
        return this;
    }

    public JceKeyTransRecipient setContentProvider(String str) {
        this.contentHelper = CMSUtils.createContentHelper(str);
        return this;
    }

    public JceKeyTransRecipient setContentProvider(Provider provider) {
        this.contentHelper = CMSUtils.createContentHelper(provider);
        return this;
    }

    public JceKeyTransRecipient setProvider(String str) {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(str));
        this.contentHelper = this.helper;
        return this;
    }

    public JceKeyTransRecipient setProvider(Provider provider) {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
        this.contentHelper = this.helper;
        return this;
    }
}
