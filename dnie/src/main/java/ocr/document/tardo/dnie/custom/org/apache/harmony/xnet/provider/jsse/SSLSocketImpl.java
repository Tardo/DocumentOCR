package custom.org.apache.harmony.xnet.provider.jsse;

import custom.org.apache.harmony.xnet.provider.jsse.Logger.Stream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class SSLSocketImpl extends SSLSocket {
    private AlertProtocol alertProtocol;
    private SSLSocketInputStream appDataIS;
    private SSLSocketOutputStream appDataOS;
    private HandshakeProtocol handshakeProtocol;
    private boolean handshake_started = false;
    protected InputStream input;
    private ArrayList<HandshakeCompletedListener> listeners;
    private Stream logger = Logger.getStream("socket");
    protected OutputStream output;
    protected SSLRecordProtocol recordProtocol;
    private SSLSessionImpl session;
    private boolean socket_was_closed = false;
    protected SSLParameters sslParameters;

    protected SSLSocketImpl(SSLParameters sslParameters) {
        this.sslParameters = sslParameters;
    }

    protected SSLSocketImpl(String host, int port, SSLParameters sslParameters) throws IOException, UnknownHostException {
        super(host, port);
        this.sslParameters = sslParameters;
        init();
    }

    protected SSLSocketImpl(String host, int port, InetAddress localHost, int localPort, SSLParameters sslParameters) throws IOException, UnknownHostException {
        super(host, port, localHost, localPort);
        this.sslParameters = sslParameters;
        init();
    }

    protected SSLSocketImpl(InetAddress host, int port, SSLParameters sslParameters) throws IOException {
        super(host, port);
        this.sslParameters = sslParameters;
        init();
    }

    protected SSLSocketImpl(InetAddress address, int port, InetAddress localAddress, int localPort, SSLParameters sslParameters) throws IOException {
        super(address, port, localAddress, localPort);
        this.sslParameters = sslParameters;
        init();
    }

    protected void init() throws IOException {
        if (this.appDataIS == null) {
            initTransportLayer();
            this.appDataIS = new SSLSocketInputStream(this);
            this.appDataOS = new SSLSocketOutputStream(this);
        }
    }

    protected void initTransportLayer() throws IOException {
        this.input = super.getInputStream();
        this.output = super.getOutputStream();
    }

    protected void closeTransportLayer() throws IOException {
        super.close();
        if (this.input != null) {
            this.input.close();
            this.output.close();
        }
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
        if (this.handshake_started) {
            throw new IllegalArgumentException("Could not change the mode after the initial handshake has begun.");
        }
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

    public SSLSession getSession() {
        if (!this.handshake_started) {
            try {
                startHandshake();
            } catch (IOException e) {
                return SSLSessionImpl.NULL_SESSION;
            }
        }
        return this.session;
    }

    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("Provided listener is null");
        }
        if (this.listeners == null) {
            this.listeners = new ArrayList();
        }
        this.listeners.add(listener);
    }

    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("Provided listener is null");
        } else if (this.listeners == null) {
            throw new IllegalArgumentException("Provided listener is not registered");
        } else if (!this.listeners.remove(listener)) {
            throw new IllegalArgumentException("Provided listener is not registered");
        }
    }

    public void startHandshake() throws IOException {
        if (this.appDataIS == null) {
            throw new IOException("Socket is not connected.");
        } else if (this.socket_was_closed) {
            throw new IOException("Socket has already been closed.");
        } else {
            if (!this.handshake_started) {
                this.handshake_started = true;
                if (this.sslParameters.getUseClientMode()) {
                    if (this.logger != null) {
                        this.logger.println("SSLSocketImpl: CLIENT");
                    }
                    this.handshakeProtocol = new ClientHandshakeImpl(this);
                } else {
                    if (this.logger != null) {
                        this.logger.println("SSLSocketImpl: SERVER");
                    }
                    this.handshakeProtocol = new ServerHandshakeImpl(this);
                }
                this.alertProtocol = new AlertProtocol();
                this.recordProtocol = new SSLRecordProtocol(this.handshakeProtocol, this.alertProtocol, new SSLStreamedInput(this.input), this.appDataIS.dataPoint);
            }
            if (this.logger != null) {
                this.logger.println("SSLSocketImpl.startHandshake");
            }
            this.handshakeProtocol.start();
            doHandshake();
            if (this.logger != null) {
                this.logger.println("SSLSocketImpl.startHandshake: END");
            }
        }
    }

    public InputStream getInputStream() throws IOException {
        if (!this.socket_was_closed) {
            return this.appDataIS;
        }
        throw new IOException("Socket has already been closed.");
    }

    public OutputStream getOutputStream() throws IOException {
        if (!this.socket_was_closed) {
            return this.appDataOS;
        }
        throw new IOException("Socket has already been closed.");
    }

    public void connect(SocketAddress endpoint) throws IOException {
        super.connect(endpoint);
        init();
    }

    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        super.connect(endpoint, timeout);
        init();
    }

    public void close() throws IOException {
        if (this.logger != null) {
            this.logger.println("SSLSocket.close " + this.socket_was_closed);
        }
        if (!this.socket_was_closed) {
            if (this.handshake_started) {
                this.alertProtocol.alert((byte) 1, (byte) 0);
                try {
                    this.output.write(this.alertProtocol.wrap());
                } catch (IOException e) {
                }
                this.alertProtocol.setProcessed();
            }
            shutdown();
            closeTransportLayer();
            this.socket_was_closed = true;
        }
    }

    public void sendUrgentData(int data) throws IOException {
        throw new SocketException("Method sendUrgentData() is not supported.");
    }

    public void setOOBInline(boolean on) throws SocketException {
        throw new SocketException("Methods sendUrgentData, setOOBInline are not supported.");
    }

    public void shutdownOutput() {
        throw new UnsupportedOperationException("Method shutdownOutput() is not supported.");
    }

    public void shutdownInput() {
        throw new UnsupportedOperationException("Method shutdownInput() is not supported.");
    }

    public String toString() {
        return "[SSLSocketImpl]";
    }

    private void shutdown() {
        if (this.handshake_started) {
            this.alertProtocol.shutdown();
            this.alertProtocol = null;
            this.handshakeProtocol.shutdown();
            this.handshakeProtocol = null;
            this.recordProtocol.shutdown();
            this.recordProtocol = null;
        }
        this.socket_was_closed = true;
    }

    protected void needAppData() throws IOException {
        if (!this.handshake_started) {
            startHandshake();
        }
        if (this.logger != null) {
            this.logger.println("SSLSocket.needAppData..");
        }
        do {
            try {
                if (this.appDataIS.available() == 0) {
                    int type = this.recordProtocol.unwrap();
                    switch (type) {
                        case 21:
                            processAlert();
                            if (this.socket_was_closed) {
                                return;
                            }
                            break;
                        case 22:
                            if (!this.handshakeProtocol.getStatus().equals(HandshakeStatus.NOT_HANDSHAKING)) {
                                doHandshake();
                                break;
                            }
                            break;
                        case 23:
                            if (this.logger != null) {
                                this.logger.println("SSLSocket.needAppData: got the data");
                                break;
                            }
                            break;
                        default:
                            reportFatalAlert((byte) 10, new SSLException("Unexpected message of type " + type + " has been got"));
                            break;
                    }
                    if (this.alertProtocol.hasAlert()) {
                        this.output.write(this.alertProtocol.wrap());
                        this.alertProtocol.setProcessed();
                    }
                } else if (this.logger != null) {
                    this.logger.println("SSLSocket.needAppData: app data len: " + this.appDataIS.available());
                    return;
                } else {
                    return;
                }
            } catch (AlertException e) {
                reportFatalAlert(e.getDescriptionCode(), e.getReason());
            } catch (EndOfSourceException e2) {
                this.appDataIS.setEnd();
            }
        } while (!this.socket_was_closed);
        this.appDataIS.setEnd();
    }

    protected void writeAppData(byte[] data, int offset, int len) throws IOException {
        if (!this.handshake_started) {
            startHandshake();
        }
        if (this.logger != null) {
            this.logger.println("SSLSocket.writeAppData: " + len + " " + 16384);
        }
        if (len < 16384) {
            try {
                this.output.write(this.recordProtocol.wrap((byte) 23, data, offset, len));
                return;
            } catch (AlertException e) {
                reportFatalAlert(e.getDescriptionCode(), e.getReason());
                return;
            }
        }
        while (len >= 16384) {
            this.output.write(this.recordProtocol.wrap((byte) 23, data, offset, 16384));
            offset += 16384;
            len -= 16384;
        }
        if (len > 0) {
            this.output.write(this.recordProtocol.wrap((byte) 23, data, offset, len));
        }
    }

    private void doHandshake() throws IOException {
        while (true) {
            try {
                HandshakeStatus status = this.handshakeProtocol.getStatus();
                if (status.equals(HandshakeStatus.FINISHED)) {
                    break;
                }
                if (this.logger != null) {
                    String s = status.equals(HandshakeStatus.NEED_WRAP) ? "NEED_WRAP" : status.equals(HandshakeStatus.NEED_UNWRAP) ? "NEED_UNWRAP" : "STATUS: OTHER!";
                    this.logger.println("SSLSocketImpl: HS status: " + s + " " + status);
                }
                if (status.equals(HandshakeStatus.NEED_WRAP)) {
                    this.output.write(this.handshakeProtocol.wrap());
                } else if (status.equals(HandshakeStatus.NEED_UNWRAP)) {
                    int type = this.recordProtocol.unwrap();
                    switch (type) {
                        case 20:
                        case 22:
                        case 23:
                            break;
                        case 21:
                            processAlert();
                            if (this.socket_was_closed) {
                                return;
                            }
                            break;
                        default:
                            reportFatalAlert((byte) 10, new SSLException("Unexpected message of type " + type + " has been got"));
                            break;
                    }
                } else {
                    reportFatalAlert((byte) 80, new SSLException("Handshake passed unexpected status: " + status));
                }
                if (this.alertProtocol.hasAlert()) {
                    this.output.write(this.alertProtocol.wrap());
                    this.alertProtocol.setProcessed();
                }
            } catch (EndOfSourceException e) {
                this.appDataIS.setEnd();
                throw new IOException("Connection was closed");
            } catch (AlertException e2) {
                reportFatalAlert(e2.getDescriptionCode(), e2.getReason());
            }
        }
        this.session = this.recordProtocol.getSession();
        if (this.listeners != null) {
            HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, this.session);
            int size = this.listeners.size();
            for (int i = 0; i < size; i++) {
                ((HandshakeCompletedListener) this.listeners.get(i)).handshakeCompleted(event);
            }
        }
    }

    private void processAlert() throws IOException {
        if (!this.alertProtocol.hasAlert()) {
            return;
        }
        if (this.alertProtocol.isFatalAlert()) {
            this.alertProtocol.setProcessed();
            String description = "Fatal alert received " + this.alertProtocol.getAlertDescription();
            shutdown();
            throw new SSLException(description);
        }
        if (this.logger != null) {
            this.logger.println("Warning alert received: " + this.alertProtocol.getAlertDescription());
        }
        switch (this.alertProtocol.getDescriptionCode()) {
            case (byte) 0:
                this.alertProtocol.setProcessed();
                this.appDataIS.setEnd();
                close();
                return;
            default:
                this.alertProtocol.setProcessed();
                return;
        }
    }

    private void reportFatalAlert(byte description_code, SSLException reason) throws IOException {
        this.alertProtocol.alert((byte) 2, description_code);
        try {
            this.output.write(this.alertProtocol.wrap());
        } catch (IOException e) {
        }
        this.alertProtocol.setProcessed();
        shutdown();
        throw reason;
    }
}
