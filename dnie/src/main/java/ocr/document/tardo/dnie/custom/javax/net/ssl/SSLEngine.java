package custom.javax.net.ssl;

import custom.javax.net.ssl.SSLEngineResult.HandshakeStatus;
import java.nio.ByteBuffer;

public abstract class SSLEngine {
    private final String peerHost;
    private final int peerPort;

    public abstract void beginHandshake() throws SSLException;

    public abstract void closeInbound() throws SSLException;

    public abstract void closeOutbound();

    public abstract Runnable getDelegatedTask();

    public abstract boolean getEnableSessionCreation();

    public abstract String[] getEnabledCipherSuites();

    public abstract String[] getEnabledProtocols();

    public abstract HandshakeStatus getHandshakeStatus();

    public abstract boolean getNeedClientAuth();

    public abstract SSLSession getSession();

    public abstract String[] getSupportedCipherSuites();

    public abstract String[] getSupportedProtocols();

    public abstract boolean getUseClientMode();

    public abstract boolean getWantClientAuth();

    public abstract boolean isInboundDone();

    public abstract boolean isOutboundDone();

    public abstract void setEnableSessionCreation(boolean z);

    public abstract void setEnabledCipherSuites(String[] strArr);

    public abstract void setEnabledProtocols(String[] strArr);

    public abstract void setNeedClientAuth(boolean z);

    public abstract void setUseClientMode(boolean z);

    public abstract void setWantClientAuth(boolean z);

    public abstract SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer[] byteBufferArr, int i, int i2) throws SSLException;

    public abstract SSLEngineResult wrap(ByteBuffer[] byteBufferArr, int i, int i2, ByteBuffer byteBuffer) throws SSLException;

    protected SSLEngine() {
        this.peerHost = null;
        this.peerPort = -1;
    }

    protected SSLEngine(String host, int port) {
        this.peerHost = host;
        this.peerPort = port;
    }

    public String getPeerHost() {
        return this.peerHost;
    }

    public int getPeerPort() {
        return this.peerPort;
    }

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return unwrap(src, new ByteBuffer[]{dst}, 0, 1);
    }

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
        if (dsts != null) {
            return unwrap(src, dsts, 0, dsts.length);
        }
        throw new IllegalArgumentException("Byte buffer array dsts is null");
    }

    public SSLEngineResult wrap(ByteBuffer[] srcs, ByteBuffer dst) throws SSLException {
        if (srcs != null) {
            return wrap(srcs, 0, srcs.length, dst);
        }
        throw new IllegalArgumentException("Byte buffer array srcs is null");
    }

    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return wrap(new ByteBuffer[]{src}, 0, 1, dst);
    }
}
