package de.tsenger.androsmex.iso7816;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.Arrays;

public final class CommandAPDU implements Serializable {
    private static final int MAX_APDU_SIZE = 65544;
    private static final long serialVersionUID = 398698301286670877L;
    private byte[] apdu;
    private transient int dataOffset;
    private transient int nc;
    private transient int ne;

    public CommandAPDU(byte[] apdu) {
        this.apdu = (byte[]) apdu.clone();
        parse();
    }

    public CommandAPDU(byte[] apdu, int apduOffset, int apduLength) {
        checkArrayBounds(apdu, apduOffset, apduLength);
        this.apdu = new byte[apduLength];
        System.arraycopy(apdu, apduOffset, this.apdu, 0, apduLength);
        parse();
    }

    private void checkArrayBounds(byte[] b, int ofs, int len) {
        if (ofs < 0 || len < 0) {
            throw new IllegalArgumentException("Offset and length must not be negative");
        } else if (b == null) {
            if (ofs != 0 && len != 0) {
                throw new IllegalArgumentException("offset and length must be 0 if array is null");
            }
        } else if (ofs > b.length - len) {
            throw new IllegalArgumentException("Offset plus length exceed array size");
        }
    }

    public CommandAPDU(ByteBuffer apdu) {
        this.apdu = new byte[apdu.remaining()];
        apdu.get(this.apdu);
        parse();
    }

    public CommandAPDU(int cla, int ins, int p1, int p2) {
        this(cla, ins, p1, p2, null, 0, 0, 0);
    }

    public CommandAPDU(int cla, int ins, int p1, int p2, int ne) {
        this(cla, ins, p1, p2, null, 0, 0, ne);
    }

    public CommandAPDU(int cla, int ins, int p1, int p2, byte[] data) {
        this(cla, ins, p1, p2, data, 0, arrayLength(data), 0);
    }

    public CommandAPDU(int cla, int ins, int p1, int p2, byte[] data, int dataOffset, int dataLength) {
        this(cla, ins, p1, p2, data, dataOffset, dataLength, 0);
    }

    public CommandAPDU(int cla, int ins, int p1, int p2, byte[] data, int ne) {
        this(cla, ins, p1, p2, data, 0, arrayLength(data), ne);
    }

    private static int arrayLength(byte[] b) {
        return b != null ? b.length : 0;
    }

    private void parse() {
        int i = 65536;
        int i2 = 256;
        if (this.apdu.length < 4) {
            throw new IllegalArgumentException("apdu must be at least 4 bytes long");
        } else if (this.apdu.length != 4) {
            int l1 = this.apdu[4] & 255;
            if (this.apdu.length == 5) {
                if (l1 == 0) {
                    l1 = 256;
                }
                this.ne = l1;
            } else if (l1 != 0) {
                if (this.apdu.length == l1 + 5) {
                    this.nc = l1;
                    this.dataOffset = 5;
                } else if (this.apdu.length == l1 + 6) {
                    this.nc = l1;
                    this.dataOffset = 5;
                    l2 = this.apdu[this.apdu.length - 1] & 255;
                    if (l2 != 0) {
                        i2 = l2;
                    }
                    this.ne = i2;
                } else {
                    throw new IllegalArgumentException("Invalid APDU: length=" + this.apdu.length + ", b1=" + l1);
                }
            } else if (this.apdu.length < 7) {
                throw new IllegalArgumentException("Invalid APDU: length=" + this.apdu.length + ", b1=" + l1);
            } else {
                l2 = ((this.apdu[5] & 255) << 8) | (this.apdu[6] & 255);
                if (this.apdu.length == 7) {
                    if (l2 == 0) {
                        l2 = 65536;
                    }
                    this.ne = l2;
                } else if (l2 == 0) {
                    throw new IllegalArgumentException("Invalid APDU: length=" + this.apdu.length + ", b1=" + l1 + ", b2||b3=" + l2);
                } else if (this.apdu.length == l2 + 7) {
                    this.nc = l2;
                    this.dataOffset = 7;
                } else if (this.apdu.length == l2 + 9) {
                    this.nc = l2;
                    this.dataOffset = 7;
                    int leOfs = this.apdu.length - 2;
                    int l3 = ((this.apdu[leOfs] & 255) << 8) | (this.apdu[leOfs + 1] & 255);
                    if (l3 != 0) {
                        i = l3;
                    }
                    this.ne = i;
                } else {
                    throw new IllegalArgumentException("Invalid APDU: length=" + this.apdu.length + ", b1=" + l1 + ", b2||b3=" + l2);
                }
            }
        }
    }

    public CommandAPDU(int cla, int ins, int p1, int p2, byte[] data, int dataOffset, int dataLength, int ne) {
        checkArrayBounds(data, dataOffset, dataLength);
        if (dataLength > 65535) {
            throw new IllegalArgumentException("dataLength is too large");
        } else if (ne < 0) {
            throw new IllegalArgumentException("ne must not be negative");
        } else if (ne > 65536) {
            throw new IllegalArgumentException("ne is too large");
        } else {
            this.ne = ne;
            this.nc = dataLength;
            if (dataLength == 0) {
                if (ne == 0) {
                    this.apdu = new byte[4];
                    setHeader(cla, ins, p1, p2);
                } else if (ne <= 256) {
                    byte len = ne != 256 ? (byte) ne : (byte) 0;
                    this.apdu = new byte[5];
                    setHeader(cla, ins, p1, p2);
                    this.apdu[4] = len;
                } else {
                    byte l1;
                    byte l2;
                    if (ne == 65536) {
                        l1 = (byte) 0;
                        l2 = (byte) 0;
                    } else {
                        l1 = (byte) (ne >> 8);
                        l2 = (byte) ne;
                    }
                    this.apdu = new byte[7];
                    setHeader(cla, ins, p1, p2);
                    this.apdu[5] = l1;
                    this.apdu[6] = l2;
                }
            } else if (ne == 0) {
                if (dataLength <= 255) {
                    this.apdu = new byte[(dataLength + 5)];
                    setHeader(cla, ins, p1, p2);
                    this.apdu[4] = (byte) dataLength;
                    this.dataOffset = 5;
                    System.arraycopy(data, dataOffset, this.apdu, 5, dataLength);
                    return;
                }
                this.apdu = new byte[(dataLength + 7)];
                setHeader(cla, ins, p1, p2);
                this.apdu[4] = (byte) 0;
                this.apdu[5] = (byte) (dataLength >> 8);
                this.apdu[6] = (byte) dataLength;
                this.dataOffset = 7;
                System.arraycopy(data, dataOffset, this.apdu, 7, dataLength);
            } else if (dataLength > 255 || ne > 256) {
                this.apdu = new byte[(dataLength + 9)];
                setHeader(cla, ins, p1, p2);
                this.apdu[4] = (byte) 0;
                this.apdu[5] = (byte) (dataLength >> 8);
                this.apdu[6] = (byte) dataLength;
                this.dataOffset = 7;
                System.arraycopy(data, dataOffset, this.apdu, 7, dataLength);
                if (ne != 65536) {
                    int leOfs = this.apdu.length - 2;
                    this.apdu[leOfs] = (byte) (ne >> 8);
                    this.apdu[leOfs + 1] = (byte) ne;
                }
            } else {
                this.apdu = new byte[(dataLength + 6)];
                setHeader(cla, ins, p1, p2);
                this.apdu[4] = (byte) dataLength;
                this.dataOffset = 5;
                System.arraycopy(data, dataOffset, this.apdu, 5, dataLength);
                this.apdu[this.apdu.length - 1] = ne != 256 ? (byte) ne : (byte) 0;
            }
        }
    }

    private void setHeader(int cla, int ins, int p1, int p2) {
        this.apdu[0] = (byte) cla;
        this.apdu[1] = (byte) ins;
        this.apdu[2] = (byte) p1;
        this.apdu[3] = (byte) p2;
    }

    public int getCLA() {
        return this.apdu[0] & 255;
    }

    public int getINS() {
        return this.apdu[1] & 255;
    }

    public int getP1() {
        return this.apdu[2] & 255;
    }

    public int getP2() {
        return this.apdu[3] & 255;
    }

    public int getNc() {
        return this.nc;
    }

    public byte[] getData() {
        byte[] data = new byte[this.nc];
        System.arraycopy(this.apdu, this.dataOffset, data, 0, this.nc);
        return data;
    }

    public int getNe() {
        return this.ne;
    }

    public byte[] getBytes() {
        return (byte[]) this.apdu.clone();
    }

    public String toString() {
        return "CommmandAPDU: " + this.apdu.length + " bytes, nc=" + this.nc + ", ne=" + this.ne;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CommandAPDU)) {
            return false;
        }
        return Arrays.equals(this.apdu, ((CommandAPDU) obj).apdu);
    }

    public int hashCode() {
        return Arrays.hashCode(this.apdu);
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.apdu = (byte[]) in.readUnshared();
        parse();
    }
}
