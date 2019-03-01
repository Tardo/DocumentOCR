package custom.org.apache.harmony.xnet.provider.jsse;

import custom.org.apache.harmony.xnet.provider.jsse.Logger.Stream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLServerSocket;

public class SSLServerSocketImpl extends SSLServerSocket {
    private Stream logger = Logger.getStream("ssocket");
    private final SSLParameters sslParameters;

    protected SSLServerSocketImpl(SSLParameters sslParameters) throws IOException {
        this.sslParameters = sslParameters;
    }

    protected SSLServerSocketImpl(int port, SSLParameters sslParameters) throws IOException {
        super(port);
        this.sslParameters = sslParameters;
    }

    protected SSLServerSocketImpl(int port, int backlog, SSLParameters sslParameters) throws IOException {
        super(port, backlog);
        this.sslParameters = sslParameters;
    }

    protected SSLServerSocketImpl(int port, int backlog, InetAddress iAddress, SSLParameters sslParameters) throws IOException {
        super(port, backlog, iAddress);
        this.sslParameters = sslParameters;
    }

    public String[] getSupportedCipherSuites() {
        return CipherSuite.getSupportedCipherSuiteNames();
    }

    public String[] getEnabledCipherSuites() {
        return this.sslParameters.getEnabledCipherSuites();
    }

    public void setEnabledCipherSuites(String[] suites) {
        this.sslParameters.setEnabledCipherSuites(suites);
    }

    public String[] getSupportedProtocols() {
        return (String[]) ProtocolVersion.supportedProtocols.clone();
    }

    public String[] getEnabledProtocols() {
        return this.sslParameters.getEnabledProtocols();
    }

    public void setEnabledProtocols(String[] protocols) {
        this.sslParameters.setEnabledProtocols(protocols);
    }

    public void setUseClientMode(boolean mode) {
        this.sslParameters.setUseClientMode(mode);
    }

    public boolean getUseClientMode() {
        return this.sslParameters.getUseClientMode();
    }

    public void setNeedClientAuth(boolean need) {
        this.sslParameters.setNeedClientAuth(need);
    }

    public boolean getNeedClientAuth() {
        return this.sslParameters.getNeedClientAuth();
    }

    public void setWantClientAuth(boolean want) {
        this.sslParameters.setWantClientAuth(want);
    }

    public boolean getWantClientAuth() {
        return this.sslParameters.getWantClientAuth();
    }

    public void setEnableSessionCreation(boolean flag) {
        this.sslParameters.setEnableSessionCreation(flag);
    }

    public boolean getEnableSessionCreation() {
        return this.sslParameters.getEnableSessionCreation();
    }

    public Socket accept() throws IOException {
        if (this.logger != null) {
            this.logger.println("SSLServerSocketImpl.accept ..");
        }
        SSLSocketImpl s = new SSLSocketImpl((SSLParameters) this.sslParameters.clone());
        implAccept(s);
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            try {
                sm.checkAccept(s.getInetAddress().getHostAddress(), s.getPort());
            } catch (SecurityException e) {
                s.close();
                throw e;
            }
        }
        s.init();
        s.startHandshake();
        if (this.logger != null) {
            this.logger.println("SSLServerSocketImpl: accepted, initialized");
        }
        return s;
    }

    public String toString() {
        return "[SSLServerSocketImpl]";
    }
}
