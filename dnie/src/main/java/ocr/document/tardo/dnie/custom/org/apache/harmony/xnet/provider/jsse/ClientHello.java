package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

public class ClientHello extends Message {
    final CipherSuite[] cipher_suites;
    final byte[] client_version;
    final byte[] compression_methods;
    final byte[] random;
    final byte[] session_id;

    public ClientHello(SecureRandom sr, byte[] version, byte[] ses_id, CipherSuite[] cipher_suite) {
        this.random = new byte[32];
        this.client_version = version;
        long gmt_unix_time = System.currentTimeMillis() / 1000;
        sr.nextBytes(this.random);
        this.random[0] = (byte) ((int) (gmt_unix_time & 255));
        this.random[1] = (byte) ((int) (gmt_unix_time & 255));
        this.random[2] = (byte) ((int) (gmt_unix_time & 255));
        this.random[3] = (byte) ((int) (gmt_unix_time & 255));
        this.session_id = ses_id;
        this.cipher_suites = cipher_suite;
        this.compression_methods = new byte[]{(byte) 0};
        this.length = ((this.session_id.length + 38) + (this.cipher_suites.length << 1)) + this.compression_methods.length;
    }

    public ClientHello(HandshakeIODataStream in, int length) throws IOException {
        this.random = new byte[32];
        this.client_version = new byte[2];
        this.client_version[0] = (byte) in.readUint8();
        this.client_version[1] = (byte) in.readUint8();
        in.read(this.random, 0, 32);
        int size = in.read();
        this.session_id = new byte[size];
        in.read(this.session_id, 0, size);
        int l = in.readUint16();
        if ((l & 1) == 1) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect ClientHello");
        }
        size = l >> 1;
        this.cipher_suites = new CipherSuite[size];
        for (int i = 0; i < size; i++) {
            this.cipher_suites[i] = CipherSuite.getByCode((byte) in.read(), (byte) in.read());
        }
        size = in.read();
        this.compression_methods = new byte[size];
        in.read(this.compression_methods, 0, size);
        this.length = ((this.session_id.length + 38) + (this.cipher_suites.length << 1)) + this.compression_methods.length;
        if (this.length > length) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect ClientHello");
        }
        if (this.length < length) {
            in.skip((long) (length - this.length));
            this.length = length;
        }
    }

    public ClientHello(HandshakeIODataStream in) throws IOException {
        this.random = new byte[32];
        if (in.readUint8() != 1) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect V2ClientHello");
        }
        this.client_version = new byte[2];
        this.client_version[0] = (byte) in.readUint8();
        this.client_version[1] = (byte) in.readUint8();
        int cipher_spec_length = in.readUint16();
        if (in.readUint16() != 0) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect V2ClientHello, cannot be used for resuming");
        }
        int challenge_length = in.readUint16();
        if (challenge_length < 16) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect V2ClientHello, short challenge data");
        }
        this.session_id = new byte[0];
        this.cipher_suites = new CipherSuite[(cipher_spec_length / 3)];
        for (int i = 0; i < this.cipher_suites.length; i++) {
            this.cipher_suites[i] = CipherSuite.getByCode((byte) in.read(), (byte) in.read(), (byte) in.read());
        }
        this.compression_methods = new byte[]{(byte) 0};
        if (challenge_length < 32) {
            Arrays.fill(this.random, 0, 32 - challenge_length, (byte) 0);
            System.arraycopy(in.read(challenge_length), 0, this.random, 32 - challenge_length, challenge_length);
        } else if (challenge_length == 32) {
            System.arraycopy(in.read(32), 0, this.random, 0, 32);
        } else {
            System.arraycopy(in.read(challenge_length), challenge_length - 32, this.random, 0, 32);
        }
        if (in.available() > 0) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect V2ClientHello, extra data");
        }
        this.length = ((this.session_id.length + 38) + (this.cipher_suites.length << 1)) + this.compression_methods.length;
    }

    public void send(HandshakeIODataStream out) {
        out.write(this.client_version);
        out.write(this.random);
        out.writeUint8((long) this.session_id.length);
        out.write(this.session_id);
        out.writeUint16((long) (this.cipher_suites.length << 1));
        for (CipherSuite toBytes : this.cipher_suites) {
            out.write(toBytes.toBytes());
        }
        out.writeUint8((long) this.compression_methods.length);
        for (byte write : this.compression_methods) {
            out.write(write);
        }
    }

    public byte[] getRandom() {
        return this.random;
    }

    public int getType() {
        return 1;
    }
}
