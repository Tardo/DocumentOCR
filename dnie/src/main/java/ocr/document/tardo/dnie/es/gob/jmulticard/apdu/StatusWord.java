package es.gob.jmulticard.apdu;

import es.gob.jmulticard.HexUtils;
import java.io.Serializable;

public final class StatusWord implements Serializable {
    private static final long serialVersionUID = -735824987343408119L;
    private byte lsb = (byte) 0;
    private byte msb = (byte) 0;

    public StatusWord(byte msb, byte lsb) {
        this.msb = msb;
        this.lsb = lsb;
    }

    public byte getMsb() {
        return this.msb;
    }

    public byte getLsb() {
        return this.lsb;
    }

    public byte[] getBytes() {
        return new byte[]{this.msb, this.lsb};
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof StatusWord)) {
            return false;
        }
        StatusWord other = (StatusWord) obj;
        if (this.lsb == other.lsb && this.msb == other.msb) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return HexUtils.getShort(new byte[]{this.msb, this.lsb}, 0);
    }

    public String toString() {
        return HexUtils.hexify(new byte[]{this.msb, this.lsb}, true);
    }
}
