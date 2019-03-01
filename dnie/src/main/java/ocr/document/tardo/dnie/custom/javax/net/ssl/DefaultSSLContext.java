package custom.javax.net.ssl;

import custom.org.apache.harmony.security.fortress.Engine;
import custom.org.apache.harmony.security.fortress.Services;
import java.io.FileInputStream;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;

final class DefaultSSLContext {
    private static SSLContext defaultSSLContext;

    /* renamed from: custom.javax.net.ssl.DefaultSSLContext$1 */
    static class C00431 implements PrivilegedAction<SSLContext> {
        C00431() {
        }

        public SSLContext run() {
            return DefaultSSLContext.findDefault();
        }
    }

    DefaultSSLContext() {
    }

    static synchronized SSLContext getContext() {
        SSLContext sSLContext;
        synchronized (DefaultSSLContext.class) {
            if (defaultSSLContext == null) {
                defaultSSLContext = (SSLContext) AccessController.doPrivileged(new C00431());
            }
            sSLContext = defaultSSLContext;
        }
        return sSLContext;
    }

    private static SSLContext findDefault() {
        for (Provider provider : Services.getProvidersList()) {
            Service service = Engine.door.getService(provider, "SSLContext");
            if (service != null) {
                FileInputStream fis;
                try {
                    SSLContext con = new SSLContext((SSLContextSpi) service.newInstance(null), service.getProvider(), service.getAlgorithm());
                    KeyManager[] keyManagers = null;
                    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                    String keystore = System.getProperty("andjavax.net.ssl.keyStore");
                    String keystorepwd = System.getProperty("andjavax.net.ssl.keyStorePassword");
                    char[] pwd = null;
                    if (keystorepwd != null) {
                        pwd = keystorepwd.toCharArray();
                    }
                    if (keystore != null) {
                        fis = new FileInputStream(keystore);
                        ks.load(fis, pwd);
                        fis.close();
                        String kmfAlg = Security.getProperty("ssl.KeyManagerFactory.algorithm");
                        if (kmfAlg == null) {
                            kmfAlg = "SunX509";
                        }
                        KeyManagerFactory kmf = KeyManagerFactory.getInstance(kmfAlg);
                        kmf.init(ks, pwd);
                        keyManagers = kmf.getKeyManagers();
                    }
                    TrustManager[] trustManagers = null;
                    keystore = System.getProperty("andjavax.net.ssl.trustStore");
                    keystorepwd = System.getProperty("andjavax.net.ssl.trustStorePassword");
                    pwd = null;
                    if (keystorepwd != null) {
                        pwd = keystorepwd.toCharArray();
                    }
                    if (keystore != null) {
                        fis = new FileInputStream(keystore);
                        ks.load(fis, pwd);
                        fis.close();
                        String tmfAlg = Security.getProperty("ssl.TrustManagerFactory.algorithm");
                        if (tmfAlg == null) {
                            tmfAlg = "PKIX";
                        }
                        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlg);
                        tmf.init(ks);
                        trustManagers = tmf.getTrustManagers();
                    }
                    con.init(keyManagers, trustManagers, null);
                    return con;
                } catch (Exception e) {
                } catch (Throwable th) {
                    fis.close();
                }
            }
        }
        return null;
    }
}
