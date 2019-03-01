package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

public class ServerKeyExchange extends Message {
    final byte[] bytes1;
    final byte[] bytes2;
    final byte[] bytes3;
    final byte[] hash;
    private RSAPublicKey key;
    final BigInteger par1;
    final BigInteger par2;
    final BigInteger par3;

    public ServerKeyExchange(BigInteger par1, BigInteger par2, BigInteger par3, byte[] hash) {
        this.par1 = par1;
        this.par2 = par2;
        this.par3 = par3;
        this.hash = hash;
        byte[] bb = this.par1.toByteArray();
        if (bb[0] == (byte) 0) {
            this.bytes1 = new byte[(bb.length - 1)];
            System.arraycopy(bb, 1, this.bytes1, 0, this.bytes1.length);
        } else {
            this.bytes1 = bb;
        }
        bb = this.par2.toByteArray();
        if (bb[0] == (byte) 0) {
            this.bytes2 = new byte[(bb.length - 1)];
            System.arraycopy(bb, 1, this.bytes2, 0, this.bytes2.length);
        } else {
            this.bytes2 = bb;
        }
        this.length = (this.bytes1.length + 4) + this.bytes2.length;
        if (hash != null) {
            this.length += hash.length + 2;
        }
        if (par3 == null) {
            this.bytes3 = null;
            return;
        }
        bb = this.par3.toByteArray();
        if (bb[0] == (byte) 0) {
            this.bytes3 = new byte[(bb.length - 1)];
            System.arraycopy(bb, 1, this.bytes3, 0, this.bytes3.length);
        } else {
            this.bytes3 = bb;
        }
        this.length += this.bytes3.length + 2;
    }

    public ServerKeyExchange(HandshakeIODataStream in, int length, int keyExchange) throws IOException {
        this.bytes1 = in.read(in.readUint16());
        this.par1 = new BigInteger(1, this.bytes1);
        this.length = this.bytes1.length + 2;
        this.bytes2 = in.read(in.readUint16());
        this.par2 = new BigInteger(1, this.bytes2);
        this.length += this.bytes2.length + 2;
        if (keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
            this.bytes3 = in.read(in.readUint16());
            this.par3 = new BigInteger(1, this.bytes3);
            this.length += this.bytes3.length + 2;
        } else {
            this.par3 = null;
            this.bytes3 = null;
        }
        if (keyExchange == CipherSuite.KeyExchange_DH_anon_EXPORT || keyExchange == CipherSuite.KeyExchange_DH_anon) {
            this.hash = null;
        } else {
            this.hash = in.read(in.readUint16());
            this.length += this.hash.length + 2;
        }
        if (this.length != length) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect ServerKeyExchange");
        }
    }

    public void send(HandshakeIODataStream out) {
        out.writeUint16((long) this.bytes1.length);
        out.write(this.bytes1);
        out.writeUint16((long) this.bytes2.length);
        out.write(this.bytes2);
        if (this.bytes3 != null) {
            out.writeUint16((long) this.bytes3.length);
            out.write(this.bytes3);
        }
        if (this.hash != null) {
            out.writeUint16((long) this.hash.length);
            out.write(this.hash);
        }
    }

    public RSAPublicKey getRSAPublicKey() {
        if (this.key != null) {
            return this.key;
        }
        try {
            this.key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(this.par1, this.par2));
            return this.key;
        } catch (Exception e) {
            return null;
        }
    }

    public int getType() {
        return 12;
    }
}
