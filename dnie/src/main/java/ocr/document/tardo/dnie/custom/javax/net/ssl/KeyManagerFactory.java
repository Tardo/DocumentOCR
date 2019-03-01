package custom.javax.net.ssl;

import custom.org.apache.harmony.security.fortress.Engine;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;

public class KeyManagerFactory {
    private static final String PROPERTY_NAME = "ssl.KeyManagerFactory.algorithm";
    private static final String SERVICE = "KeyManagerFactory";
    private static Engine engine = new Engine(SERVICE);
    private final String algorithm;
    private final Provider provider;
    private final KeyManagerFactorySpi spiImpl;

    /* renamed from: custom.javax.net.ssl.KeyManagerFactory$1 */
    static class C00441 implements PrivilegedAction<String> {
        C00441() {
        }

        public String run() {
            return Security.getProperty(KeyManagerFactory.PROPERTY_NAME);
        }
    }

    public static final String getDefaultAlgorithm() {
        return (String) AccessController.doPrivileged(new C00441());
    }

    public static final KeyManagerFactory getInstance(String algorithm) throws NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NullPointerException("algorithm is null");
        }
        KeyManagerFactory keyManagerFactory;
        synchronized (engine) {
            engine.getInstance(algorithm, null);
            keyManagerFactory = new KeyManagerFactory((KeyManagerFactorySpi) engine.spi, engine.provider, algorithm);
        }
        return keyManagerFactory;
    }

    public static final KeyManagerFactory getInstance(String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (provider == null || provider.length() == 0) {
            throw new IllegalArgumentException("Provider is null or empty");
        }
        Provider impProvider = Security.getProvider(provider);
        if (impProvider != null) {
            return getInstance(algorithm, impProvider);
        }
        throw new NoSuchProviderException(provider);
    }

    public static final KeyManagerFactory getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException("Provider is null");
        } else if (algorithm == null) {
            throw new NullPointerException("algorithm is null");
        } else {
            KeyManagerFactory keyManagerFactory;
            synchronized (engine) {
                engine.getInstance(algorithm, provider, null);
                keyManagerFactory = new KeyManagerFactory((KeyManagerFactorySpi) engine.spi, provider, algorithm);
            }
            return keyManagerFactory;
        }
    }

    protected KeyManagerFactory(KeyManagerFactorySpi factorySpi, Provider provider, String algorithm) {
        this.provider = provider;
        this.algorithm = algorithm;
        this.spiImpl = factorySpi;
    }

    public final String getAlgorithm() {
        return this.algorithm;
    }

    public final Provider getProvider() {
        return this.provider;
    }

    public final void init(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.spiImpl.engineInit(ks, password);
    }

    public final void init(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        this.spiImpl.engineInit(spec);
    }

    public final KeyManager[] getKeyManagers() {
        return this.spiImpl.engineGetKeyManagers();
    }
}
