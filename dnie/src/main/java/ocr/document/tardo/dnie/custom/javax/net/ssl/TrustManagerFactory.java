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

public class TrustManagerFactory {
    private static final String PROPERTYNAME = "ssl.TrustManagerFactory.algorithm";
    private static final String SERVICE = "TrustManagerFactory";
    private static Engine engine = new Engine(SERVICE);
    private final String algorithm;
    private final Provider provider;
    private final TrustManagerFactorySpi spiImpl;

    /* renamed from: custom.javax.net.ssl.TrustManagerFactory$1 */
    static class C00471 implements PrivilegedAction<String> {
        C00471() {
        }

        public String run() {
            return Security.getProperty(TrustManagerFactory.PROPERTYNAME);
        }
    }

    public static final String getDefaultAlgorithm() {
        return (String) AccessController.doPrivileged(new C00471());
    }

    public static final TrustManagerFactory getInstance(String algorithm) throws NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NullPointerException("algorithm is null");
        }
        TrustManagerFactory trustManagerFactory;
        synchronized (engine) {
            engine.getInstance(algorithm, null);
            trustManagerFactory = new TrustManagerFactory((TrustManagerFactorySpi) engine.spi, engine.provider, algorithm);
        }
        return trustManagerFactory;
    }

    public static final TrustManagerFactory getInstance(String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (provider == null || provider.length() == 0) {
            throw new IllegalArgumentException("Provider is null oe empty");
        }
        Provider impProvider = Security.getProvider(provider);
        if (impProvider != null) {
            return getInstance(algorithm, impProvider);
        }
        throw new NoSuchProviderException(provider);
    }

    public static final TrustManagerFactory getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException("Provider is null");
        } else if (algorithm == null) {
            throw new NullPointerException("algorithm is null");
        } else {
            TrustManagerFactory trustManagerFactory;
            synchronized (engine) {
                engine.getInstance(algorithm, provider, null);
                trustManagerFactory = new TrustManagerFactory((TrustManagerFactorySpi) engine.spi, provider, algorithm);
            }
            return trustManagerFactory;
        }
    }

    protected TrustManagerFactory(TrustManagerFactorySpi factorySpi, Provider provider, String algorithm) {
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

    public final void init(KeyStore ks) throws KeyStoreException {
        this.spiImpl.engineInit(ks);
    }

    public final void init(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        this.spiImpl.engineInit(spec);
    }

    public final TrustManager[] getTrustManagers() {
        return this.spiImpl.engineGetTrustManagers();
    }
}
