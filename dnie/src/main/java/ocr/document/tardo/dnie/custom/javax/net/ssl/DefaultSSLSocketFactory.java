package custom.javax.net.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;

class DefaultSSLSocketFactory extends SSLSocketFactory {
    private final String errMessage;

    DefaultSSLSocketFactory(String mes) {
        this.errMessage = mes;
    }

    public String[] getDefaultCipherSuites() {
        return new String[0];
    }

    public String[] getSupportedCipherSuites() {
        return new String[0];
    }

    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        throw new SocketException(this.errMessage);
    }

    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        throw new SocketException(this.errMessage);
    }

    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        throw new SocketException(this.errMessage);
    }

    public Socket createSocket(InetAddress host, int port) throws IOException {
        throw new SocketException(this.errMessage);
    }

    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        throw new SocketException(this.errMessage);
    }
}
