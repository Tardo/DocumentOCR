package org.bouncycastle.cms.jcajce;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;

public class JceAlgorithmIdentifierConverter {
    private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    private SecureRandom random;

    public AlgorithmParameters getAlgorithmParameters(AlgorithmIdentifier algorithmIdentifier) throws CMSException {
        ASN1Encodable parameters = algorithmIdentifier.getParameters();
        if (parameters == null) {
            return null;
        }
        try {
            AlgorithmParameters createAlgorithmParameters = this.helper.createAlgorithmParameters(algorithmIdentifier.getAlgorithm());
            createAlgorithmParameters.init(parameters.toASN1Primitive().getEncoded(), "ASN.1");
            return createAlgorithmParameters;
        } catch (Exception e) {
            throw new CMSException("can't find parameters for algorithm", e);
        } catch (Exception e2) {
            throw new CMSException("can't parse parameters", e2);
        } catch (Exception e22) {
            throw new CMSException("can't find provider for algorithm", e22);
        }
    }

    public JceAlgorithmIdentifierConverter setProvider(String str) {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(str));
        return this;
    }

    public JceAlgorithmIdentifierConverter setProvider(Provider provider) {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
        return this;
    }
}
