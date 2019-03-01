package custom.org.apache.harmony.xnet.provider.jsse;

import custom.org.apache.harmony.xnet.provider.jsse.Logger.Stream;
import java.io.IOException;
import javax.net.ssl.SSLProtocolException;
import org.bouncycastle.asn1.eac.CertificateBody;

public class SSLRecordProtocol {
    protected static final int MAX_CIPHERED_DATA_LENGTH = 18432;
    protected static final int MAX_COMPRESSED_DATA_LENGTH = 17408;
    protected static final int MAX_DATA_LENGTH = 16384;
    protected static final int MAX_SSL_PACKET_SIZE = 18437;
    private static final byte[] change_cipher_spec_byte = new byte[]{(byte) 1};
    private ConnectionState activeReadState;
    private ConnectionState activeWriteState;
    private AlertProtocol alertProtocol;
    private Appendable appData;
    private HandshakeProtocol handshakeProtocol;
    private SSLInputStream in;
    private Stream logger = Logger.getStream("record");
    private ConnectionState pendingConnectionState;
    private SSLSessionImpl session;
    private boolean sessionWasChanged = false;
    private byte[] version;

    protected SSLRecordProtocol(HandshakeProtocol handshakeProtocol, AlertProtocol alertProtocol, SSLInputStream in, Appendable appData) {
        this.handshakeProtocol = handshakeProtocol;
        this.handshakeProtocol.setRecordProtocol(this);
        this.alertProtocol = alertProtocol;
        this.alertProtocol.setRecordProtocol(this);
        this.in = in;
        this.appData = appData;
    }

    protected SSLSessionImpl getSession() {
        return this.session;
    }

    protected int getMinRecordSize() {
        return this.activeReadState == null ? 6 : this.activeReadState.getMinFragmentSize() + 5;
    }

    protected int getRecordSize(int data_size) {
        if (this.activeWriteState == null) {
            return data_size + 5;
        }
        int res = this.activeWriteState.getFragmentSize(data_size) + 5;
        return res > MAX_CIPHERED_DATA_LENGTH ? MAX_CIPHERED_DATA_LENGTH : res;
    }

    protected int getDataSize(int record_size) {
        record_size -= 5;
        if (record_size > MAX_CIPHERED_DATA_LENGTH) {
            return 16384;
        }
        return this.activeReadState != null ? this.activeReadState.getContentSize(record_size) : record_size;
    }

    protected byte[] wrap(byte content_type, DataStream dataStream) {
        byte[] fragment = dataStream.getData(16384);
        return wrap(content_type, fragment, 0, fragment.length);
    }

    protected byte[] wrap(byte content_type, byte[] fragment, int offset, int len) {
        if (this.logger != null) {
            this.logger.println("SSLRecordProtocol.wrap: TLSPlaintext.fragment[" + len + "]:");
            this.logger.print(fragment, offset, len);
        }
        if (len > 16384) {
            throw new AlertException((byte) 80, new SSLProtocolException("The provided chunk of data is too big: " + len + " > MAX_DATA_LENGTH == " + 16384));
        }
        byte[] ciphered_fragment = fragment;
        if (this.activeWriteState != null) {
            ciphered_fragment = this.activeWriteState.encrypt(content_type, fragment, offset, len);
            if (ciphered_fragment.length > MAX_CIPHERED_DATA_LENGTH) {
                throw new AlertException((byte) 80, new SSLProtocolException("The ciphered data increased more than on 1024 bytes"));
            } else if (this.logger != null) {
                this.logger.println("SSLRecordProtocol.wrap: TLSCiphertext.fragment[" + ciphered_fragment.length + "]:");
                this.logger.print(ciphered_fragment);
            }
        }
        return packetize(content_type, this.version, ciphered_fragment);
    }

    private byte[] packetize(byte type, byte[] version, byte[] fragment) {
        byte[] buff = new byte[(fragment.length + 5)];
        buff[0] = type;
        if (version != null) {
            buff[1] = version[0];
            buff[2] = version[1];
        } else {
            buff[1] = (byte) 3;
            buff[2] = (byte) 1;
        }
        buff[3] = (byte) ((65280 & fragment.length) >> 8);
        buff[4] = (byte) (fragment.length & 255);
        System.arraycopy(fragment, 0, buff, 5, fragment.length);
        return buff;
    }

    private void setSession(SSLSessionImpl session) {
        if (this.sessionWasChanged) {
            this.sessionWasChanged = false;
            return;
        }
        if (this.logger != null) {
            this.logger.println("SSLRecordProtocol.setSession: Set pending session");
            this.logger.println("  cipher name: " + session.getCipherSuite());
        }
        this.session = session;
        ConnectionState connectionStateTLS = (this.version == null || this.version[1] == (byte) 1) ? new ConnectionStateTLS(getSession()) : new ConnectionStateSSLv3(getSession());
        this.pendingConnectionState = connectionStateTLS;
        this.sessionWasChanged = true;
    }

    protected byte[] getChangeCipherSpecMesage(SSLSessionImpl session) {
        byte[] change_cipher_spec_message = this.activeWriteState == null ? new byte[]{Handshake.FINISHED, this.version[0], this.version[1], (byte) 0, (byte) 1, (byte) 1} : packetize(Handshake.FINISHED, this.version, this.activeWriteState.encrypt(Handshake.FINISHED, change_cipher_spec_byte, 0, 1));
        setSession(session);
        this.activeWriteState = this.pendingConnectionState;
        if (this.logger != null) {
            this.logger.println("SSLRecordProtocol.getChangeCipherSpecMesage");
            this.logger.println("activeWriteState = pendingConnectionState");
            this.logger.print(change_cipher_spec_message);
        }
        return change_cipher_spec_message;
    }

    protected int unwrap() throws IOException {
        if (this.logger != null) {
            this.logger.println("SSLRecordProtocol.unwrap: BEGIN [");
        }
        int type = this.in.readUint8();
        if (type < 20 || type > 23) {
            if (this.logger != null) {
                this.logger.println("Non v3.1 message type:" + type);
            }
            if (type >= 128) {
                this.handshakeProtocol.unwrapSSLv2(this.in.read(((type & CertificateBody.profileType) << 8) | this.in.read()));
                if (this.logger != null) {
                    this.logger.println("SSLRecordProtocol:unwrap ] END, SSLv2 type");
                }
                return 22;
            }
            throw new AlertException((byte) 10, new SSLProtocolException("Unexpected message type has been received: " + type));
        }
        if (this.logger != null) {
            this.logger.println("Got the message of type: " + type);
        }
        if (this.version == null) {
            this.in.skip(2);
        } else if (!(this.in.read() == this.version[0] && this.in.read() == this.version[1])) {
            throw new AlertException((byte) 10, new SSLProtocolException("Unexpected message type has been received: " + type));
        }
        int length = this.in.readUint16();
        if (this.logger != null) {
            this.logger.println("TLSCiphertext.fragment[" + length + "]: ...");
        }
        if (length > MAX_CIPHERED_DATA_LENGTH) {
            throw new AlertException((byte) 22, new SSLProtocolException("Received message is too big."));
        }
        byte[] fragment = this.in.read(length);
        if (this.logger != null) {
            this.logger.print(fragment);
        }
        if (this.activeReadState != null) {
            fragment = this.activeReadState.decrypt((byte) type, fragment);
            if (this.logger != null) {
                this.logger.println("TLSPlaintext.fragment:");
                this.logger.print(fragment);
            }
        }
        if (fragment.length > 16384) {
            throw new AlertException((byte) 30, new SSLProtocolException("Decompressed plain data is too big."));
        }
        switch (type) {
            case 20:
                this.handshakeProtocol.receiveChangeCipherSpec();
                setSession(this.handshakeProtocol.getSession());
                if (this.logger != null) {
                    this.logger.println("activeReadState = pendingConnectionState");
                }
                this.activeReadState = this.pendingConnectionState;
                break;
            case 21:
                alert(fragment[0], fragment[1]);
                break;
            case 22:
                this.handshakeProtocol.unwrap(fragment);
                break;
            case 23:
                if (this.logger != null) {
                    this.logger.println("TLSCiphertext.unwrap: APP DATA[" + length + "]:");
                    this.logger.println(new String(fragment));
                }
                this.appData.append(fragment);
                break;
            default:
                throw new AlertException((byte) 10, new SSLProtocolException("Unexpected message type has been received: " + type));
        }
        if (this.logger == null) {
            return type;
        }
        this.logger.println("SSLRecordProtocol:unwrap ] END, type: " + type);
        return type;
    }

    protected void alert(byte level, byte description) {
        if (this.logger != null) {
            this.logger.println("SSLRecordProtocol.allert: " + level + " " + description);
        }
        this.alertProtocol.alert(level, description);
    }

    protected void setVersion(byte[] ver) {
        this.version = ver;
    }

    protected void shutdown() {
        this.session = null;
        this.version = null;
        this.in = null;
        this.handshakeProtocol = null;
        this.alertProtocol = null;
        this.appData = null;
        if (this.pendingConnectionState != null) {
            this.pendingConnectionState.shutdown();
        }
        this.pendingConnectionState = null;
        if (this.activeReadState != null) {
            this.activeReadState.shutdown();
        }
        this.activeReadState = null;
        if (this.activeWriteState != null) {
            this.activeWriteState.shutdown();
        }
        this.activeWriteState = null;
    }
}
