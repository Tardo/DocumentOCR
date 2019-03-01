package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.cert.CertificateException;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

public class TrustManagerFactoryImpl extends TrustManagerFactorySpi {
    private KeyStore keyStore;

    /* renamed from: custom.org.apache.harmony.xnet.provider.jsse.TrustManagerFactoryImpl$1 */
    class C00631 implements PrivilegedAction<String> {
        C00631() {
        }

        public String run() {
            return System.getProperty("javax.net.ssl.trustStore");
        }
    }

    /* renamed from: custom.org.apache.harmony.xnet.provider.jsse.TrustManagerFactoryImpl$2 */
    class C00642 implements PrivilegedAction<String> {
        C00642() {
        }

        public String run() {
            return System.getProperty("javax.net.ssl.trustStorePassword");
        }
    }

    public void engineInit(KeyStore ks) throws KeyStoreException {
        if (ks != null) {
            this.keyStore = ks;
            return;
        }
        this.keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        String keyStoreName = (String) AccessController.doPrivileged(new C00631());
        if (keyStoreName == null || keyStoreName.equalsIgnoreCase("NONE") || keyStoreName.length() == 0) {
            try {
                this.keyStore.load(null, null);
                return;
            } catch (IOException e) {
                throw new KeyStoreException(e);
            } catch (CertificateException e2) {
                throw new KeyStoreException(e2);
            } catch (NoSuchAlgorithmException e3) {
                throw new KeyStoreException(e3);
            }
        }
        char[] pwd;
        String keyStorePwd = (String) AccessController.doPrivileged(new C00642());
        if (keyStorePwd == null) {
            pwd = new char[0];
        } else {
            pwd = keyStorePwd.toCharArray();
        }
        try {
            this.keyStore.load(new FileInputStream(new File(keyStoreName)), pwd);
        } catch (FileNotFoundException e4) {
            throw new KeyStoreException(e4);
        } catch (IOException e5) {
            throw new KeyStoreException(e5);
        } catch (CertificateException e22) {
            throw new KeyStoreException(e22);
        } catch (NoSuchAlgorithmException e32) {
            throw new KeyStoreException(e32);
        }
    }

    public void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
    }

    public TrustManager[] engineGetTrustManagers() {
        if (this.keyStore == null) {
            throw new IllegalStateException("TrustManagerFactory is not initialized");
        }
        return new TrustManager[]{new TrustManagerImpl(this.keyStore)};
    }
}
