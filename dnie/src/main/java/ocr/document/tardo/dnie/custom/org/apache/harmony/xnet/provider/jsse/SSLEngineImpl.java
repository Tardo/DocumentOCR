package custom.org.apache.harmony.xnet.provider.jsse;

import custom.org.apache.harmony.xnet.provider.jsse.Logger.Stream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import org.bouncycastle.asn1.eac.EACTags;

public class SSLEngineImpl extends SSLEngine {
    private AlertProtocol alertProtocol;
    private SSLEngineAppData appData;
    private boolean close_notify_was_received = false;
    private boolean close_notify_was_sent = false;
    private SSLEngineDataStream dataStream = new SSLEngineDataStream();
    private boolean engine_was_closed = false;
    private boolean engine_was_shutteddown = false;
    private HandshakeProtocol handshakeProtocol;
    private boolean handshake_started = false;
    private boolean isInboundDone = false;
    private boolean isOutboundDone = false;
    private Stream logger = Logger.getStream("engine");
    private boolean peer_mode_was_set = false;
    private SSLBufferedInput recProtIS;
    protected SSLRecordProtocol recordProtocol;
    private byte[] remaining_hsh_data = null;
    private byte[] remaining_wrapped_data = null;
    private SSLSessionImpl session;
    protected SSLParameters sslParameters;

    protected SSLEngineImpl(SSLParameters sslParameters) {
        this.sslParameters = sslParameters;
    }

    protected SSLEngineImpl(String host, int port, SSLParameters sslParameters) {
        super(host, port);
        this.sslParameters = sslParameters;
    }

    public void beginHandshake() throws SSLException {
        if (this.engine_was_closed) {
            throw new SSLException("Engine has already been closed.");
        } else if (this.peer_mode_was_set) {
            if (!this.handshake_started) {
                this.handshake_started = true;
                if (getUseClientMode()) {
                    this.handshakeProtocol = new ClientHandshakeImpl(this);
                } else {
                    this.handshakeProtocol = new ServerHandshakeImpl(this);
                }
                this.appData = new SSLEngineAppData();
                this.alertProtocol = new AlertProtocol();
                this.recProtIS = new SSLBufferedInput();
                this.recordProtocol = new SSLRecordProtocol(this.handshakeProtocol, this.alertProtocol, this.recProtIS, this.appData);
            }
            this.handshakeProtocol.start();
        } else {
            throw new IllegalStateException("Client/Server mode was not set");
        }
    }

    public void closeInbound() throws SSLException {
        if (this.logger != null) {
            this.logger.println("closeInbound() " + this.isInboundDone);
        }
        if (!this.isInboundDone) {
            this.isInboundDone = true;
            this.engine_was_closed = true;
            if (!this.handshake_started) {
                shutdown();
            } else if (!this.close_notify_was_received) {
                if (this.session != null) {
                    this.session.invalidate();
                }
                this.alertProtocol.alert((byte) 2, (byte) 80);
                throw new SSLException("Inbound is closed before close_notify alert has been received.");
            }
        }
    }

    public void closeOutbound() {
        if (this.logger != null) {
            this.logger.println("closeOutbound() " + this.isOutboundDone);
        }
        if (!this.isOutboundDone) {
            this.isOutboundDone = true;
            if (this.handshake_started) {
                this.alertProtocol.alert((byte) 1, (byte) 0);
                this.close_notify_was_sent = true;
            } else {
                shutdown();
            }
            this.engine_was_closed = true;
        }
    }

    public Runnable getDelegatedTask() {
        return this.handshakeProtocol.getTask();
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
        this.peer_mode_was_set = true;
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

    public HandshakeStatus getHandshakeStatus() {
        if (!this.handshake_started || this.engine_was_shutteddown) {
            return HandshakeStatus.NOT_HANDSHAKING;
        }
        if (this.alertProtocol.hasAlert()) {
            return HandshakeStatus.NEED_WRAP;
        }
        if (!this.close_notify_was_sent || this.close_notify_was_received) {
            return this.handshakeProtocol.getStatus();
        }
        return HandshakeStatus.NEED_UNWRAP;
    }

    public SSLSession getSession() {
        if (this.session != null) {
            return this.session;
        }
        return SSLSessionImpl.NULL_SESSION;
    }

    public boolean isInboundDone() {
        return this.isInboundDone || this.engine_was_closed;
    }

    public boolean isOutboundDone() {
        return this.isOutboundDone;
    }

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
        if (this.engine_was_shutteddown) {
            return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
        }
        if (src == null || dsts == null) {
            throw new IllegalStateException("Some of the input parameters are null");
        }
        if (!this.handshake_started) {
            beginHandshake();
        }
        HandshakeStatus handshakeStatus = getHandshakeStatus();
        if ((this.session == null || this.engine_was_closed) && (handshakeStatus.equals(HandshakeStatus.NEED_WRAP) || handshakeStatus.equals(HandshakeStatus.NEED_TASK))) {
            return new SSLEngineResult(getEngineStatus(), handshakeStatus, 0, 0);
        }
        if (src.remaining() < this.recordProtocol.getMinRecordSize()) {
            return new SSLEngineResult(Status.BUFFER_UNDERFLOW, getHandshakeStatus(), 0, 0);
        }
        try {
            src.mark();
            int capacity = 0;
            int i = offset;
            while (i < offset + length) {
                if (dsts[i] == null) {
                    throw new IllegalStateException("Some of the input parameters are null");
                } else if (dsts[i].isReadOnly()) {
                    throw new ReadOnlyBufferException();
                } else {
                    capacity += dsts[i].remaining();
                    i++;
                }
            }
            if (capacity < this.recordProtocol.getDataSize(src.remaining())) {
                return new SSLEngineResult(Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
            }
            this.recProtIS.setSourceBuffer(src);
            switch (this.recordProtocol.unwrap()) {
                case 20:
                case 22:
                    if (this.handshakeProtocol.getStatus().equals(HandshakeStatus.FINISHED)) {
                        this.session = this.recordProtocol.getSession();
                        break;
                    }
                    break;
                case 21:
                    if (!this.alertProtocol.isFatalAlert()) {
                        if (this.logger != null) {
                            this.logger.println("Warning allert has been received: " + this.alertProtocol.getAlertDescription());
                        }
                        switch (this.alertProtocol.getDescriptionCode()) {
                            case (byte) 0:
                                this.alertProtocol.setProcessed();
                                this.close_notify_was_received = true;
                                if (!this.close_notify_was_sent) {
                                    closeOutbound();
                                    closeInbound();
                                    break;
                                }
                                closeInbound();
                                shutdown();
                                break;
                            case EACTags.FMD_TEMPLATE /*100*/:
                                this.alertProtocol.setProcessed();
                                if (this.session != null) {
                                    this.handshakeProtocol.stop();
                                    break;
                                }
                                throw new AlertException((byte) 40, new SSLHandshakeException("Received no_renegotiation during the initial handshake"));
                            default:
                                this.alertProtocol.setProcessed();
                                break;
                        }
                    }
                    this.alertProtocol.setProcessed();
                    if (this.session != null) {
                        this.session.invalidate();
                    }
                    String description = "Fatal alert received " + this.alertProtocol.getAlertDescription();
                    shutdown();
                    throw new SSLException(description);
            }
            return new SSLEngineResult(getEngineStatus(), getHandshakeStatus(), this.recProtIS.consumed(), this.appData.placeTo(dsts, offset, length));
        } catch (BufferUnderflowException e) {
            src.reset();
            return new SSLEngineResult(Status.BUFFER_UNDERFLOW, getHandshakeStatus(), 0, 0);
        } catch (AlertException e2) {
            this.alertProtocol.alert((byte) 2, e2.getDescriptionCode());
            this.engine_was_closed = true;
            src.reset();
            if (this.session != null) {
                this.session.invalidate();
            }
            throw e2.getReason();
        } catch (SSLException e3) {
            throw e3;
        } catch (IOException e4) {
            this.alertProtocol.alert((byte) 2, (byte) 80);
            this.engine_was_closed = true;
            throw new SSLException(e4.getMessage());
        }
    }

    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int len, ByteBuffer dst) throws SSLException {
        if (this.engine_was_shutteddown) {
            return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
        }
        if (srcs == null || dst == null) {
            throw new IllegalStateException("Some of the input parameters are null");
        } else if (dst.isReadOnly()) {
            throw new ReadOnlyBufferException();
        } else {
            if (!this.handshake_started) {
                beginHandshake();
            }
            HandshakeStatus handshakeStatus = getHandshakeStatus();
            if ((this.session == null || this.engine_was_closed) && (handshakeStatus.equals(HandshakeStatus.NEED_UNWRAP) || handshakeStatus.equals(HandshakeStatus.NEED_TASK))) {
                return new SSLEngineResult(getEngineStatus(), handshakeStatus, 0, 0);
            }
            int capacity = dst.remaining();
            if (this.alertProtocol.hasAlert()) {
                if (capacity < this.recordProtocol.getRecordSize(2)) {
                    return new SSLEngineResult(Status.BUFFER_OVERFLOW, handshakeStatus, 0, 0);
                }
                byte[] alert_data = this.alertProtocol.wrap();
                dst.put(alert_data);
                if (this.alertProtocol.isFatalAlert()) {
                    this.alertProtocol.setProcessed();
                    if (this.session != null) {
                        this.session.invalidate();
                    }
                    shutdown();
                    return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, alert_data.length);
                }
                this.alertProtocol.setProcessed();
                if (!this.close_notify_was_sent || !this.close_notify_was_received) {
                    return new SSLEngineResult(getEngineStatus(), getHandshakeStatus(), 0, alert_data.length);
                }
                shutdown();
                return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, alert_data.length);
            } else if (capacity < this.recordProtocol.getMinRecordSize()) {
                if (this.logger != null) {
                    this.logger.println("Capacity of the destination(" + capacity + ") < MIN_PACKET_SIZE(" + this.recordProtocol.getMinRecordSize() + ")");
                }
                return new SSLEngineResult(Status.BUFFER_OVERFLOW, handshakeStatus, 0, 0);
            } else {
                try {
                    int produced;
                    if (handshakeStatus.equals(HandshakeStatus.NEED_WRAP)) {
                        if (this.remaining_hsh_data == null) {
                            this.remaining_hsh_data = this.handshakeProtocol.wrap();
                        }
                        if (capacity < this.remaining_hsh_data.length) {
                            return new SSLEngineResult(Status.BUFFER_OVERFLOW, handshakeStatus, 0, 0);
                        }
                        dst.put(this.remaining_hsh_data);
                        produced = this.remaining_hsh_data.length;
                        this.remaining_hsh_data = null;
                        if (this.handshakeProtocol.getStatus().equals(HandshakeStatus.FINISHED)) {
                            this.session = this.recordProtocol.getSession();
                        }
                        return new SSLEngineResult(getEngineStatus(), getHandshakeStatus(), 0, produced);
                    }
                    this.dataStream.setSourceBuffers(srcs, offset, len);
                    if (capacity >= 18437 || capacity >= this.recordProtocol.getRecordSize(this.dataStream.available())) {
                        if (this.remaining_wrapped_data == null) {
                            this.remaining_wrapped_data = this.recordProtocol.wrap((byte) 23, this.dataStream);
                        }
                        if (capacity < this.remaining_wrapped_data.length) {
                            return new SSLEngineResult(Status.BUFFER_OVERFLOW, handshakeStatus, this.dataStream.consumed(), 0);
                        }
                        dst.put(this.remaining_wrapped_data);
                        produced = this.remaining_wrapped_data.length;
                        this.remaining_wrapped_data = null;
                        return new SSLEngineResult(getEngineStatus(), handshakeStatus, this.dataStream.consumed(), produced);
                    }
                    if (this.logger != null) {
                        this.logger.println("The destination buffer(" + capacity + ") can not take the resulting packet(" + this.recordProtocol.getRecordSize(this.dataStream.available()) + ")");
                    }
                    return new SSLEngineResult(Status.BUFFER_OVERFLOW, handshakeStatus, 0, 0);
                } catch (AlertException e) {
                    this.alertProtocol.alert((byte) 2, e.getDescriptionCode());
                    this.engine_was_closed = true;
                    if (this.session != null) {
                        this.session.invalidate();
                    }
                    throw e.getReason();
                }
            }
        }
    }

    private void shutdown() {
        this.engine_was_closed = true;
        this.engine_was_shutteddown = true;
        this.isOutboundDone = true;
        this.isInboundDone = true;
        if (this.handshake_started) {
            this.alertProtocol.shutdown();
            this.alertProtocol = null;
            this.handshakeProtocol.shutdown();
            this.handshakeProtocol = null;
            this.recordProtocol.shutdown();
            this.recordProtocol = null;
        }
    }

    private Status getEngineStatus() {
        return this.engine_was_closed ? Status.CLOSED : Status.OK;
    }
}
