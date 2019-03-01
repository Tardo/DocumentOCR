package es.inteco.labs.net.auth;

import custom.org.apache.harmony.xnet.provider.jsse.DNIeJSSEProvider;
import es.inteco.labs.net.HashedCertificatesOnlyTrustManager;
import es.inteco.labs.net.auth.dnie.DNIeKeyManagerImpl;
import es.inteco.labs.net.exception.SSLProviderNotFoundException;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.Set;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;

public class ClientCertSSLSocketFactory extends SSLSocketFactory {
    private SSLContext sslContext;

    static {
        Security.insertProviderAt(new DNIeJSSEProvider(), 1);
    }

    public ClientCertSSLSocketFactory(KeyStore keyStore, KeyStore truststore, Set<String> onlyTrustedCerts) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(truststore);
        try {
            this.sslContext = SSLContext.getInstance("TLSv1", "DnieHarmonyJSSE");
            this.sslContext.init(new KeyManager[]{new DNIeKeyManagerImpl(keyStore, null)}, new TrustManager[]{new HashedCertificatesOnlyTrustManager(truststore, onlyTrustedCerts)}, null);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            this.sslContext = null;
            throw new SSLProviderNotFoundException(e);
        }
    }

    public ClientCertSSLSocketFactory(KeyStore keyStore, KeyStore truststore) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(truststore);
        try {
            this.sslContext = SSLContext.getInstance("TLSv1", "DnieHarmonyJSSE");
            TrustManagerFactory trustManFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManFactory.init(truststore);
            this.sslContext.init(new KeyManager[]{new DNIeKeyManagerImpl(keyStore, null)}, trustManFactory.getTrustManagers(), null);
        } catch (NoSuchProviderException e) {
            this.sslContext = null;
            throw new SSLProviderNotFoundException(e);
        }
    }

    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException, UnknownHostException {
        return this.sslContext.getSocketFactory().createSocket(socket, host, port, autoClose);
    }

    public Socket createSocket() throws IOException {
        return this.sslContext.getSocketFactory().createSocket();
    }
}
