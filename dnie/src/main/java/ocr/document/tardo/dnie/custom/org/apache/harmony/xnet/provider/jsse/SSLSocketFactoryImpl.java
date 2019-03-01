package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import javax.net.ssl.SSLSocketFactory;

public class SSLSocketFactoryImpl extends SSLSocketFactory {
    private IOException instantiationException;
    private SSLParameters sslParameters;

    public SSLSocketFactoryImpl() {
        try {
            this.sslParameters = SSLParameters.getDefault();
        } catch (KeyManagementException e) {
            this.instantiationException = new IOException("Delayed instantiation exception:");
            this.instantiationException.initCause(e);
        }
    }

    protected SSLSocketFactoryImpl(SSLParameters sslParameters) {
        this.sslParameters = sslParameters;
    }

    public String[] getDefaultCipherSuites() {
        if (this.instantiationException != null) {
            return new String[0];
        }
        return this.sslParameters.getEnabledCipherSuites();
    }

    public String[] getSupportedCipherSuites() {
        if (this.instantiationException != null) {
            return new String[0];
        }
        return CipherSuite.getSupportedCipherSuiteNames();
    }

    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        if (this.instantiationException == null) {
            return new SSLSocketWrapper(s, autoClose, (SSLParameters) this.sslParameters.clone());
        }
        throw this.instantiationException;
    }

    public Socket createSocket() throws IOException {
        if (this.instantiationException == null) {
            return new SSLSocketImpl((SSLParameters) this.sslParameters.clone());
        }
        throw this.instantiationException;
    }

    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        if (this.instantiationException == null) {
            return new SSLSocketImpl(host, port, (SSLParameters) this.sslParameters.clone());
        }
        throw this.instantiationException;
    }

    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        if (this.instantiationException != null) {
            throw this.instantiationException;
        }
        return new SSLSocketImpl(host, port, localHost, localPort, (SSLParameters) this.sslParameters.clone());
    }

    public Socket createSocket(InetAddress host, int port) throws IOException {
        if (this.instantiationException == null) {
            return new SSLSocketImpl(host, port, (SSLParameters) this.sslParameters.clone());
        }
        throw this.instantiationException;
    }

    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        if (this.instantiationException != null) {
            throw this.instantiationException;
        }
        return new SSLSocketImpl(address, port, localAddress, localPort, (SSLParameters) this.sslParameters.clone());
    }
}
