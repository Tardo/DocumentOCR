package custom.javax.net.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.SocketException;

class DefaultSSLServerSocketFactory extends SSLServerSocketFactory {
    private final String errMessage;

    DefaultSSLServerSocketFactory(String mes) {
        this.errMessage = mes;
    }

    public String[] getDefaultCipherSuites() {
        return new String[0];
    }

    public String[] getSupportedCipherSuites() {
        return new String[0];
    }

    public ServerSocket createServerSocket(int port) throws IOException {
        throw new SocketException(this.errMessage);
    }

    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        throw new SocketException(this.errMessage);
    }

    public ServerSocket createServerSocket(int port, int backlog, InetAddress iAddress) throws IOException {
        throw new SocketException(this.errMessage);
    }
}
