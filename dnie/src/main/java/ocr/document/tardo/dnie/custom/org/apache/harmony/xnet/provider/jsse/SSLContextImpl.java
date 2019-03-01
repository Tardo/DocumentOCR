package custom.org.apache.harmony.xnet.provider.jsse;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class SSLContextImpl extends SSLContextSpi {
    private SSLSessionContextImpl clientSessionContext = new SSLSessionContextImpl();
    private SSLSessionContextImpl serverSessionContext = new SSLSessionContextImpl();
    protected SSLParameters sslParameters;

    public void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        this.sslParameters = new SSLParameters(kms, tms, sr, this.clientSessionContext, this.serverSessionContext);
    }

    public SSLSocketFactory engineGetSocketFactory() {
        if (this.sslParameters != null) {
            return new SSLSocketFactoryImpl(this.sslParameters);
        }
        throw new IllegalStateException("SSLContext is not initiallized.");
    }

    public SSLServerSocketFactory engineGetServerSocketFactory() {
        if (this.sslParameters != null) {
            return new SSLServerSocketFactoryImpl(this.sslParameters);
        }
        throw new IllegalStateException("SSLContext is not initiallized.");
    }

    public SSLEngine engineCreateSSLEngine(String host, int port) {
        if (this.sslParameters != null) {
            return new SSLEngineImpl(host, port, (SSLParameters) this.sslParameters.clone());
        }
        throw new IllegalStateException("SSLContext is not initiallized.");
    }

    public SSLEngine engineCreateSSLEngine() {
        if (this.sslParameters != null) {
            return new SSLEngineImpl((SSLParameters) this.sslParameters.clone());
        }
        throw new IllegalStateException("SSLContext is not initiallized.");
    }

    public SSLSessionContext engineGetServerSessionContext() {
        return this.serverSessionContext;
    }

    public SSLSessionContext engineGetClientSessionContext() {
        return this.clientSessionContext;
    }
}
