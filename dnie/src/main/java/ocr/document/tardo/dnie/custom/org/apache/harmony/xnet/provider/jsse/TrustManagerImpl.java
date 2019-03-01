package custom.org.apache.harmony.xnet.provider.jsse;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.X509TrustManager;

public class TrustManagerImpl implements X509TrustManager {
    private Exception err = null;
    private CertificateFactory factory;
    private PKIXParameters params;
    private CertPathValidator validator;

    public TrustManagerImpl(KeyStore ks) {
        try {
            this.validator = CertPathValidator.getInstance("PKIX");
            this.factory = CertificateFactory.getInstance("X509");
            Set<TrustAnchor> trusted = new HashSet();
            Enumeration<String> en = ks.aliases();
            while (en.hasMoreElements()) {
                X509Certificate cert = (X509Certificate) ks.getCertificate((String) en.nextElement());
                if (cert != null) {
                    trusted.add(new TrustAnchor(cert, null));
                }
            }
            this.params = new PKIXParameters(trusted);
            this.params.setRevocationEnabled(false);
        } catch (Exception e) {
            this.err = e;
        }
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0 || authType == null || authType.length() == 0) {
            throw new IllegalArgumentException("null or zero-length parameter");
        } else if (this.err != null) {
            throw new CertificateException(this.err);
        } else {
            try {
                this.validator.validate(this.factory.generateCertPath(Arrays.asList(chain)), this.params);
            } catch (InvalidAlgorithmParameterException e) {
                throw new CertificateException(e);
            } catch (CertPathValidatorException e2) {
                throw new CertificateException(e2);
            }
        }
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0 || authType == null || authType.length() == 0) {
            throw new IllegalArgumentException("null or zero-length parameter");
        } else if (this.err != null) {
            throw new CertificateException(this.err);
        } else {
            try {
                this.validator.validate(this.factory.generateCertPath(Arrays.asList(chain)), this.params);
            } catch (InvalidAlgorithmParameterException e) {
                throw new CertificateException(e);
            } catch (CertPathValidatorException e2) {
                throw new CertificateException(e2);
            }
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        if (this.params == null) {
            return new X509Certificate[0];
        }
        Set<TrustAnchor> anchors = this.params.getTrustAnchors();
        X509Certificate[] certs = new X509Certificate[anchors.size()];
        int i = 0;
        for (TrustAnchor trustedCert : anchors) {
            int i2 = i + 1;
            certs[i] = trustedCert.getTrustedCert();
            i = i2;
        }
        return certs;
    }
}
