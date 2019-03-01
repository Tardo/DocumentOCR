package custom.org.apache.harmony.security.provider.crypto;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.util.Arrays;

public class SHA1_MessageDigestImpl extends MessageDigestSpi implements Cloneable, SHA1_Data {
    private int[] buffer = new int[87];
    private int messageLength;
    private byte[] oneByte = new byte[1];

    public SHA1_MessageDigestImpl() {
        engineReset();
    }

    private void processDigest(byte[] digest, int offset) {
        long nBits = (long) (this.messageLength << 3);
        engineUpdate(Byte.MIN_VALUE);
        int i = 0;
        int lastWord = (this.buffer[81] + 3) >> 2;
        if (this.buffer[81] != 0) {
            if (lastWord < 15) {
                i = lastWord;
            } else {
                if (lastWord == 15) {
                    this.buffer[15] = 0;
                }
                SHA1Impl.computeHash(this.buffer);
                i = 0;
            }
        }
        Arrays.fill(this.buffer, i, 14, 0);
        this.buffer[14] = (int) (nBits >>> 32);
        this.buffer[15] = (int) (-1 & nBits);
        SHA1Impl.computeHash(this.buffer);
        int j = offset;
        for (i = 82; i < 87; i++) {
            int k = this.buffer[i];
            digest[j] = (byte) (k >>> 24);
            digest[j + 1] = (byte) (k >>> 16);
            digest[j + 2] = (byte) (k >>> 8);
            digest[j + 3] = (byte) k;
            j += 4;
        }
        engineReset();
    }

    public Object clone() throws CloneNotSupportedException {
        SHA1_MessageDigestImpl cloneObj = (SHA1_MessageDigestImpl) super.clone();
        cloneObj.buffer = (int[]) this.buffer.clone();
        cloneObj.oneByte = (byte[]) this.oneByte.clone();
        return cloneObj;
    }

    protected byte[] engineDigest() {
        byte[] hash = new byte[20];
        processDigest(hash, 0);
        return hash;
    }

    protected int engineDigest(byte[] buf, int offset, int len) throws DigestException {
        if (buf == null) {
            throw new IllegalArgumentException(Messages.getString("security.162"));
        } else if (offset > buf.length || len > buf.length || len + offset > buf.length) {
            throw new IllegalArgumentException(Messages.getString("security.163"));
        } else if (len < 20) {
            throw new DigestException(Messages.getString("security.164"));
        } else if (offset < 0) {
            throw new ArrayIndexOutOfBoundsException(Messages.getString("security.165", offset));
        } else {
            processDigest(buf, offset);
            return 20;
        }
    }

    protected int engineGetDigestLength() {
        return 20;
    }

    protected void engineReset() {
        this.messageLength = 0;
        this.buffer[81] = 0;
        this.buffer[82] = SHA1_Data.H0;
        this.buffer[83] = SHA1_Data.H1;
        this.buffer[84] = SHA1_Data.H2;
        this.buffer[85] = SHA1_Data.H3;
        this.buffer[86] = SHA1_Data.H4;
    }

    protected void engineUpdate(byte input) {
        this.oneByte[0] = input;
        SHA1Impl.updateHash(this.buffer, this.oneByte, 0, 0);
        this.messageLength++;
    }

    protected void engineUpdate(byte[] input, int offset, int len) {
        if (input == null) {
            throw new IllegalArgumentException(Messages.getString("security.166"));
        } else if (len > 0) {
            if (offset < 0) {
                throw new ArrayIndexOutOfBoundsException(Messages.getString("security.165", offset));
            } else if (offset > input.length || len > input.length || len + offset > input.length) {
                throw new IllegalArgumentException(Messages.getString("security.167"));
            } else {
                SHA1Impl.updateHash(this.buffer, input, offset, (offset + len) - 1);
                this.messageLength += len;
            }
        }
    }
}
