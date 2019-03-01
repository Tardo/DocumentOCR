package custom.org.apache.harmony.xnet.provider.jsse;

import custom.org.apache.harmony.xnet.provider.jsse.Logger.Stream;
import javax.crypto.Cipher;

public abstract class ConnectionState {
    protected Cipher decCipher;
    protected Cipher encCipher;
    protected int hash_size;
    protected boolean is_block_cipher;
    protected Stream logger = Logger.getStream("conn_state");
    protected final byte[] read_seq_num = new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0};
    protected final byte[] write_seq_num = new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0};

    protected abstract byte[] decrypt(byte b, byte[] bArr, int i, int i2);

    protected abstract byte[] encrypt(byte b, byte[] bArr, int i, int i2);

    protected int getMinFragmentSize() {
        return this.encCipher.getOutputSize(this.hash_size + 1);
    }

    protected int getFragmentSize(int content_size) {
        return this.encCipher.getOutputSize(this.hash_size + content_size);
    }

    protected int getContentSize(int generic_cipher_size) {
        return this.decCipher.getOutputSize(generic_cipher_size) - this.hash_size;
    }

    protected byte[] encrypt(byte type, byte[] fragment) {
        return encrypt(type, fragment, 0, fragment.length);
    }

    protected byte[] decrypt(byte type, byte[] fragment) {
        return decrypt(type, fragment, 0, fragment.length);
    }

    protected static void incSequenceNumber(byte[] seq_num) {
        int octet = 7;
        while (octet >= 0) {
            seq_num[octet] = (byte) (seq_num[octet] + 1);
            if (seq_num[octet] == (byte) 0) {
                octet--;
            } else {
                return;
            }
        }
    }

    protected void shutdown() {
        this.encCipher = null;
        this.decCipher = null;
        for (int i = 0; i < this.write_seq_num.length; i++) {
            this.write_seq_num[i] = (byte) 0;
            this.read_seq_num[i] = (byte) 0;
        }
    }
}
