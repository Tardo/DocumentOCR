package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.internal.nls.Messages;

public final class BitString {
    private static final byte[] RESET_MASK = new byte[]{Byte.MAX_VALUE, (byte) -65, (byte) -33, (byte) -17, (byte) -9, (byte) -5, (byte) -3, (byte) -2};
    private static final byte[] SET_MASK = new byte[]{Byte.MIN_VALUE, (byte) 64, (byte) 32, (byte) 16, (byte) 8, (byte) 4, (byte) 2, (byte) 1};
    public final byte[] bytes;
    public final int unusedBits;

    public BitString(byte[] bytes, int unusedBits) {
        if (unusedBits < 0 || unusedBits > 7) {
            throw new IllegalArgumentException(Messages.getString("security.13D"));
        } else if (bytes.length != 0 || unusedBits == 0) {
            this.bytes = bytes;
            this.unusedBits = unusedBits;
        } else {
            throw new IllegalArgumentException(Messages.getString("security.13E"));
        }
    }

    public BitString(boolean[] values) {
        this.unusedBits = values.length % 8;
        int size = values.length / 8;
        if (this.unusedBits != 0) {
            size++;
        }
        this.bytes = new byte[size];
        for (int i = 0; i < values.length; i++) {
            setBit(i, values[i]);
        }
    }

    public boolean getBit(int bit) {
        return (this.bytes[bit / 8] & SET_MASK[bit % 8]) != 0;
    }

    public void setBit(int bit, boolean value) {
        int offset = bit % 8;
        int index = bit / 8;
        if (value) {
            byte[] bArr = this.bytes;
            bArr[index] = (byte) (bArr[index] | SET_MASK[offset]);
            return;
        }
        bArr = this.bytes;
        bArr[index] = (byte) (bArr[index] & RESET_MASK[offset]);
    }

    public boolean[] toBooleanArray() {
        boolean[] result = new boolean[((this.bytes.length * 8) - this.unusedBits)];
        for (int i = 0; i < result.length; i++) {
            result[i] = getBit(i);
        }
        return result;
    }
}
