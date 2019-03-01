package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;

public class CertificateVerify extends Message {
    byte[] signedHash;

    public CertificateVerify(byte[] hash) {
        if (hash == null || hash.length == 0) {
            fatalAlert((byte) 80, "INTERNAL ERROR: incorrect certificate verify hash");
        }
        this.signedHash = hash;
        this.length = hash.length + 2;
    }

    public CertificateVerify(HandshakeIODataStream in, int length) throws IOException {
        if (length == 0) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect CertificateVerify");
        } else {
            if (in.readUint16() != length - 2) {
                fatalAlert((byte) 50, "DECODE ERROR: incorrect CertificateVerify");
            }
            this.signedHash = in.read(length - 2);
        }
        this.length = length;
    }

    public void send(HandshakeIODataStream out) {
        if (this.signedHash.length != 0) {
            out.writeUint16((long) this.signedHash.length);
            out.write(this.signedHash);
        }
    }

    public int getType() {
        return 15;
    }
}
