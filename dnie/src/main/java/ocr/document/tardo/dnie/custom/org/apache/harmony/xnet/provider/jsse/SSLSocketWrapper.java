package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;

public class SSLSocketWrapper extends SSLSocketImpl {
    private final boolean autoClose;
    private final Socket socket;

    protected SSLSocketWrapper(Socket socket, boolean autoClose, SSLParameters sslParameters) throws IOException {
        super(sslParameters);
        if (socket.isConnected()) {
            this.socket = socket;
            this.autoClose = autoClose;
            init();
            return;
        }
        throw new SocketException("Socket is not connected.");
    }

    protected void initTransportLayer() throws IOException {
        this.input = this.socket.getInputStream();
        this.output = this.socket.getOutputStream();
    }

    protected void closeTransportLayer() throws IOException {
        if (this.autoClose && this.input != null) {
            this.socket.close();
            this.input.close();
            this.output.close();
        }
    }

    public void connect(SocketAddress sockaddr, int timeout) throws IOException {
        throw new IOException("Underlying socket is already connected.");
    }

    public void connect(SocketAddress sockaddr) throws IOException {
        throw new IOException("Underlying socket is already connected.");
    }

    public void bind(SocketAddress sockaddr) throws IOException {
        throw new IOException("Underlying socket is already connected.");
    }

    public SocketAddress getRemoteSocketAddress() {
        return this.socket.getRemoteSocketAddress();
    }

    public SocketAddress getLocalSocketAddress() {
        return this.socket.getLocalSocketAddress();
    }

    public InetAddress getLocalAddress() {
        return this.socket.getLocalAddress();
    }

    public InetAddress getInetAddress() {
        return this.socket.getInetAddress();
    }

    public String toString() {
        return "SSL socket over " + this.socket.toString();
    }

    public void setSoLinger(boolean on, int linger) throws SocketException {
        this.socket.setSoLinger(on, linger);
    }

    public void setTcpNoDelay(boolean on) throws SocketException {
        this.socket.setTcpNoDelay(on);
    }

    public void setReuseAddress(boolean on) throws SocketException {
        this.socket.setReuseAddress(on);
    }

    public void setKeepAlive(boolean on) throws SocketException {
        this.socket.setKeepAlive(on);
    }

    public void setTrafficClass(int tos) throws SocketException {
        this.socket.setTrafficClass(tos);
    }

    public void setSoTimeout(int to) throws SocketException {
        this.socket.setSoTimeout(to);
    }

    public void setSendBufferSize(int size) throws SocketException {
        this.socket.setSendBufferSize(size);
    }

    public void setReceiveBufferSize(int size) throws SocketException {
        this.socket.setReceiveBufferSize(size);
    }

    public boolean getTcpNoDelay() throws SocketException {
        return this.socket.getTcpNoDelay();
    }

    public boolean getReuseAddress() throws SocketException {
        return this.socket.getReuseAddress();
    }

    public boolean getOOBInline() throws SocketException {
        return this.socket.getOOBInline();
    }

    public boolean getKeepAlive() throws SocketException {
        return this.socket.getKeepAlive();
    }

    public int getTrafficClass() throws SocketException {
        return this.socket.getTrafficClass();
    }

    public int getSoTimeout() throws SocketException {
        return this.socket.getSoTimeout();
    }

    public int getSoLinger() throws SocketException {
        return this.socket.getSoLinger();
    }

    public int getSendBufferSize() throws SocketException {
        return this.socket.getSendBufferSize();
    }

    public int getReceiveBufferSize() throws SocketException {
        return this.socket.getReceiveBufferSize();
    }

    public boolean isConnected() {
        return this.socket.isConnected();
    }

    public boolean isClosed() {
        return this.socket.isClosed();
    }

    public boolean isBound() {
        return this.socket.isBound();
    }

    public boolean isOutputShutdown() {
        return this.socket.isOutputShutdown();
    }

    public boolean isInputShutdown() {
        return this.socket.isInputShutdown();
    }

    public int getPort() {
        return this.socket.getPort();
    }

    public int getLocalPort() {
        return this.socket.getLocalPort();
    }
}
