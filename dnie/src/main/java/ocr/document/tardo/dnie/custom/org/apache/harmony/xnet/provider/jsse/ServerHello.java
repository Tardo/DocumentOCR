package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;

public class ServerHello extends Message {
    CipherSuite cipher_suite;
    byte compression_method;
    byte[] random;
    byte[] server_version;
    byte[] session_id;

    public ServerHello(SecureRandom sr, byte[] server_version, byte[] session_id, CipherSuite cipher_suite, byte compression_method) {
        this.server_version = new byte[2];
        this.random = new byte[32];
        long gmt_unix_time = new Date().getTime() / 1000;
        sr.nextBytes(this.random);
        this.random[0] = (byte) ((int) ((-16777216 & gmt_unix_time) >>> 24));
        this.random[1] = (byte) ((int) ((16711680 & gmt_unix_time) >>> 16));
        this.random[2] = (byte) ((int) ((65280 & gmt_unix_time) >>> 8));
        this.random[3] = (byte) ((int) (255 & gmt_unix_time));
        this.session_id = session_id;
        this.cipher_suite = cipher_suite;
        this.compression_method = compression_method;
        this.server_version = server_version;
        this.length = session_id.length + 38;
    }

    public ServerHello(HandshakeIODataStream in, int length) throws IOException {
        this.server_version = new byte[2];
        this.random = new byte[32];
        this.server_version[0] = (byte) in.read();
        this.server_version[1] = (byte) in.read();
        in.read(this.random, 0, 32);
        int size = in.readUint8();
        this.session_id = new byte[size];
        in.read(this.session_id, 0, size);
        this.cipher_suite = CipherSuite.getByCode((byte) in.read(), (byte) in.read());
        this.compression_method = (byte) in.read();
        this.length = this.session_id.length + 38;
        if (this.length != length) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect ServerHello");
        }
    }

    public void send(HandshakeIODataStream out) {
        out.write(this.server_version);
        out.write(this.random);
        out.writeUint8((long) this.session_id.length);
        out.write(this.session_id);
        out.write(this.cipher_suite.toBytes());
        out.write(this.compression_method);
        this.length = this.session_id.length + 38;
    }

    public byte[] getRandom() {
        return this.random;
    }

    public int getType() {
        return 2;
    }
}
