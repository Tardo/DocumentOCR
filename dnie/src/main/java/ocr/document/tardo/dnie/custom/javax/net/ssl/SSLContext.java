package custom.javax.net.ssl;

import custom.org.apache.harmony.security.fortress.Engine;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

public class SSLContext {
    private static final String SERVICE = "SSLContext";
    private static Engine engine = new Engine(SERVICE);
    private final String protocol;
    private final Provider provider;
    private final SSLContextSpi spiImpl;

    public static SSLContext getInstance(String protocol) throws NoSuchAlgorithmException {
        if (protocol == null) {
            throw new NullPointerException("protocol is null");
        }
        SSLContext sSLContext;
        synchronized (engine) {
            engine.getInstance(protocol, null);
            sSLContext = new SSLContext((SSLContextSpi) engine.spi, engine.provider, protocol);
        }
        return sSLContext;
    }

    public static SSLContext getInstance(String protocol, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (provider == null) {
            throw new IllegalArgumentException("Provider is null");
        } else if (provider.length() == 0) {
            throw new IllegalArgumentException("Provider is empty");
        } else {
            Provider impProvider = Security.getProvider(provider);
            if (impProvider != null) {
                return getInstance(protocol, impProvider);
            }
            throw new NoSuchProviderException(provider);
        }
    }

    public static SSLContext getInstance(String protocol, Provider provider) throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        } else if (protocol == null) {
            throw new NullPointerException("protocol is null");
        } else {
            SSLContext sSLContext;
            synchronized (engine) {
                engine.getInstance(protocol, provider, null);
                sSLContext = new SSLContext((SSLContextSpi) engine.spi, provider, protocol);
            }
            return sSLContext;
        }
    }

    protected SSLContext(SSLContextSpi contextSpi, Provider provider, String protocol) {
        this.provider = provider;
        this.protocol = protocol;
        this.spiImpl = contextSpi;
    }

    public final String getProtocol() {
        return this.protocol;
    }

    public final Provider getProvider() {
        return this.provider;
    }

    public final void init(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
        this.spiImpl.engineInit(km, tm, sr);
    }

    public final SSLSocketFactory getSocketFactory() {
        return this.spiImpl.engineGetSocketFactory();
    }

    public final SSLServerSocketFactory getServerSocketFactory() {
        return this.spiImpl.engineGetServerSocketFactory();
    }

    public final SSLEngine createSSLEngine() {
        return this.spiImpl.engineCreateSSLEngine();
    }

    public final SSLEngine createSSLEngine(String peerHost, int peerPort) {
        return this.spiImpl.engineCreateSSLEngine(peerHost, peerPort);
    }

    public final SSLSessionContext getServerSessionContext() {
        return this.spiImpl.engineGetServerSessionContext();
    }

    public final SSLSessionContext getClientSessionContext() {
        return this.spiImpl.engineGetClientSessionContext();
    }
}
