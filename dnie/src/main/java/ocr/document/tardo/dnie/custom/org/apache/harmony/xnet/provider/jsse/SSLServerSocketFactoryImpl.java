package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.KeyManagementException;
import javax.net.ssl.SSLServerSocketFactory;

public class SSLServerSocketFactoryImpl extends SSLServerSocketFactory {
    private IOException instantiationException;
    private SSLParameters sslParameters;

    public SSLServerSocketFactoryImpl() {
        try {
            this.sslParameters = SSLParameters.getDefault();
            this.sslParameters.setUseClientMode(false);
        } catch (KeyManagementException e) {
            this.instantiationException = new IOException("Delayed instantiation exception:");
            this.instantiationException.initCause(e);
        }
    }

    protected SSLServerSocketFactoryImpl(SSLParameters sslParameters) {
        this.sslParameters = (SSLParameters) sslParameters.clone();
        this.sslParameters.setUseClientMode(false);
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

    public ServerSocket createServerSocket() throws IOException {
        if (this.instantiationException == null) {
            return new SSLServerSocketImpl((SSLParameters) this.sslParameters.clone());
        }
        throw this.instantiationException;
    }

    public ServerSocket createServerSocket(int port) throws IOException {
        if (this.instantiationException == null) {
            return new SSLServerSocketImpl(port, (SSLParameters) this.sslParameters.clone());
        }
        throw this.instantiationException;
    }

    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        if (this.instantiationException == null) {
            return new SSLServerSocketImpl(port, backlog, (SSLParameters) this.sslParameters.clone());
        }
        throw this.instantiationException;
    }

    public ServerSocket createServerSocket(int port, int backlog, InetAddress iAddress) throws IOException {
        if (this.instantiationException == null) {
            return new SSLServerSocketImpl(port, backlog, iAddress, (SSLParameters) this.sslParameters.clone());
        }
        throw this.instantiationException;
    }
}
