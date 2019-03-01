package es.gob.jmulticard.asn1.bertlv;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;

public final class BerTlvIdentifier {
    private byte[] value;

    public int getTagValue() {
        if (this.value == null) {
            return 0;
        }
        if (this.value.length == 1) {
            return this.value[0];
        }
        byte[] tagBytes = new byte[(this.value.length - 1)];
        System.arraycopy(this.value, 1, tagBytes, 0, this.value.length - 1);
        for (int i = 0; i < tagBytes.length - 1; i++) {
            tagBytes[i] = (byte) BitManipulationHelper.setBitValue(tagBytes[i], 8, false);
        }
        return new BigInteger(tagBytes).intValue();
    }

    void decode(ByteArrayInputStream stream) {
        this.value = new byte[]{(byte) stream.read()};
        if ((stream.read() & 31) == 31) {
            boolean lastOctet;
            do {
                lastOctet = false;
                if (!BitManipulationHelper.getBitValue(stream.read(), 8)) {
                    lastOctet = true;
                }
                this.value = BitManipulationHelper.mergeArrays(this.value, new byte[]{(byte) tlvIdNextOctet});
            } while (!lastOctet);
        }
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BerTlvIdentifier)) {
            return false;
        }
        BerTlvIdentifier bti = (BerTlvIdentifier) obj;
        if (this.value.length != bti.value.length) {
            return false;
        }
        int i = 0;
        while (i < this.value.length) {
            try {
                if (this.value[i] != bti.value[i]) {
                    return false;
                }
                i++;
            } catch (ArrayIndexOutOfBoundsException e) {
                return false;
            }
        }
        return true;
    }

    public int hashCode() {
        return new BigInteger(this.value).intValue();
    }

    public String toString() {
        if (this.value == null) {
            return "NULL";
        }
        StringBuffer buf = new StringBuffer("[");
        for (byte toHexString : this.value) {
            buf.append("0x").append(Integer.toHexString(toHexString)).append(' ');
        }
        buf.append(']');
        return buf.toString();
    }
}
