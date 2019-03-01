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
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

public class KeyManagerFactoryImpl extends KeyManagerFactorySpi {
    private KeyStore keyStore;
    private char[] pwd;

    /* renamed from: custom.org.apache.harmony.xnet.provider.jsse.KeyManagerFactoryImpl$1 */
    class C00561 implements PrivilegedAction<String> {
        C00561() {
        }

        public String run() {
            return System.getProperty("javax.net.ssl.keyStore");
        }
    }

    /* renamed from: custom.org.apache.harmony.xnet.provider.jsse.KeyManagerFactoryImpl$2 */
    class C00572 implements PrivilegedAction<String> {
        C00572() {
        }

        public String run() {
            return System.getProperty("javax.net.ssl.keyStorePassword");
        }
    }

    public void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (ks != null) {
            this.keyStore = ks;
            if (password != null) {
                this.pwd = (char[]) password.clone();
                return;
            } else {
                this.pwd = new char[0];
                return;
            }
        }
        this.keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        String keyStoreName = (String) AccessController.doPrivileged(new C00561());
        if (keyStoreName == null || keyStoreName.equalsIgnoreCase("NONE") || keyStoreName.length() == 0) {
            try {
                this.keyStore.load(null, null);
                return;
            } catch (IOException e) {
                throw new KeyStoreException(e);
            } catch (CertificateException e2) {
                throw new KeyStoreException(e2);
            }
        }
        String keyStorePwd = (String) AccessController.doPrivileged(new C00572());
        if (keyStorePwd == null) {
            this.pwd = new char[0];
        } else {
            this.pwd = keyStorePwd.toCharArray();
        }
        try {
            this.keyStore.load(new FileInputStream(new File(keyStoreName)), this.pwd);
        } catch (FileNotFoundException e3) {
            throw new KeyStoreException(e3);
        } catch (IOException e4) {
            throw new KeyStoreException(e4);
        } catch (CertificateException e22) {
            throw new KeyStoreException(e22);
        }
    }

    public void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
    }

    public KeyManager[] engineGetKeyManagers() {
        if (this.keyStore == null) {
            throw new IllegalStateException("KeyManagerFactory is not initialized");
        }
        return new KeyManager[]{new KeyManagerImpl(this.keyStore, this.pwd)};
    }
}
