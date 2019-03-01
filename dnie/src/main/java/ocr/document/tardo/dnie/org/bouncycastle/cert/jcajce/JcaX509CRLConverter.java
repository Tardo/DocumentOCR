package org.bouncycastle.cert.jcajce;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import org.bouncycastle.cert.X509CRLHolder;

public class JcaX509CRLConverter {
    private CertHelper helper;

    private class ExCRLException extends CRLException {
        private Throwable cause;

        public ExCRLException(String str, Throwable th) {
            super(str);
            this.cause = th;
        }

        public Throwable getCause() {
            return this.cause;
        }
    }

    public JcaX509CRLConverter() {
        this.helper = new DefaultCertHelper();
        this.helper = new DefaultCertHelper();
    }

    public X509CRL getCRL(X509CRLHolder x509CRLHolder) throws CRLException {
        try {
            return (X509CRL) this.helper.getCertificateFactory("X.509").generateCRL(new ByteArrayInputStream(x509CRLHolder.getEncoded()));
        } catch (Throwable e) {
            throw new ExCRLException("exception parsing certificate: " + e.getMessage(), e);
        } catch (Throwable e2) {
            throw new ExCRLException("cannot find required provider:" + e2.getMessage(), e2);
        } catch (Throwable e22) {
            throw new ExCRLException("cannot create factory: " + e22.getMessage(), e22);
        }
    }

    public JcaX509CRLConverter setProvider(String str) {
        this.helper = new NamedCertHelper(str);
        return this;
    }

    public JcaX509CRLConverter setProvider(Provider provider) {
        this.helper = new ProviderCertHelper(provider);
        return this;
    }
}
