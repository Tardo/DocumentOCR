package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.math.BigInteger;

public class ClientKeyExchange extends Message {
    final byte[] exchange_keys;
    final boolean isRSA;
    boolean isTLS;

    public ClientKeyExchange(byte[] encrypted_pre_master_secret, boolean isTLS) {
        this.exchange_keys = encrypted_pre_master_secret;
        this.length = this.exchange_keys.length;
        if (isTLS) {
            this.length += 2;
        }
        this.isTLS = isTLS;
        this.isRSA = true;
    }

    public ClientKeyExchange(BigInteger dh_Yc) {
        byte[] bb = dh_Yc.toByteArray();
        if (bb[0] == (byte) 0) {
            this.exchange_keys = new byte[(bb.length - 1)];
            System.arraycopy(bb, 1, this.exchange_keys, 0, this.exchange_keys.length);
        } else {
            this.exchange_keys = bb;
        }
        this.length = this.exchange_keys.length + 2;
        this.isRSA = false;
    }

    public ClientKeyExchange() {
        this.exchange_keys = new byte[0];
        this.length = 0;
        this.isRSA = false;
    }

    public ClientKeyExchange(HandshakeIODataStream in, int length, boolean isTLS, boolean isRSA) throws IOException {
        this.isTLS = isTLS;
        this.isRSA = isRSA;
        if (length == 0) {
            this.length = 0;
            this.exchange_keys = new byte[0];
            return;
        }
        int size;
        if (!isRSA || isTLS) {
            size = in.readUint16();
            this.length = size + 2;
        } else {
            size = length;
            this.length = size;
        }
        this.exchange_keys = new byte[size];
        in.read(this.exchange_keys, 0, size);
        if (this.length != length) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect ClientKeyExchange");
        }
    }

    public void send(HandshakeIODataStream out) {
        if (this.exchange_keys.length != 0) {
            if (!this.isRSA || this.isTLS) {
                out.writeUint16((long) this.exchange_keys.length);
            }
            out.write(this.exchange_keys);
        }
    }

    public int getType() {
        return 16;
    }

    public boolean isEmpty() {
        return this.exchange_keys.length == 0;
    }
}
