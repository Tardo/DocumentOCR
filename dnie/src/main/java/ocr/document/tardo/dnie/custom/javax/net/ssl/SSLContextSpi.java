package custom.javax.net.ssl;

import java.security.KeyManagementException;
import java.security.SecureRandom;

public abstract class SSLContextSpi {
    protected abstract SSLEngine engineCreateSSLEngine();

    protected abstract SSLEngine engineCreateSSLEngine(String str, int i);

    protected abstract SSLSessionContext engineGetClientSessionContext();

    protected abstract SSLSessionContext engineGetServerSessionContext();

    protected abstract SSLServerSocketFactory engineGetServerSocketFactory();

    protected abstract SSLSocketFactory engineGetSocketFactory();

    protected abstract void engineInit(KeyManager[] keyManagerArr, TrustManager[] trustManagerArr, SecureRandom secureRandom) throws KeyManagementException;
}
