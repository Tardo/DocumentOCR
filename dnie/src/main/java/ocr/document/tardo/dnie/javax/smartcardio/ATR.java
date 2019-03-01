package javax.smartcardio;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.Arrays;

public final class ATR implements Serializable {
    private static final long serialVersionUID = 6695383790847736493L;
    private byte[] atr;
    private transient int nHistorical;
    private transient int startHistorical;

    public ATR(byte[] atr) {
        this.atr = (byte[]) atr.clone();
        parse();
    }

    private void parse() {
        if (this.atr.length >= 2) {
            if (this.atr[0] == (byte) 59 || this.atr[0] == (byte) 63) {
                int t0 = (this.atr[1] & 240) >> 4;
                int n = this.atr[1] & 15;
                int i = 2;
                while (t0 != 0 && i < this.atr.length) {
                    int i2;
                    if ((t0 & 1) != 0) {
                        i++;
                    }
                    if ((t0 & 2) != 0) {
                        i++;
                    }
                    if ((t0 & 4) != 0) {
                        i2 = i + 1;
                    } else {
                        i2 = i;
                    }
                    if ((t0 & 8) == 0) {
                        t0 = 0;
                        i = i2;
                    } else if (i2 < this.atr.length) {
                        i = i2 + 1;
                        t0 = (this.atr[i2] & 240) >> 4;
                    } else {
                        return;
                    }
                }
                int k = i + n;
                if (k == this.atr.length || k == this.atr.length - 1) {
                    this.startHistorical = i;
                    this.nHistorical = n;
                }
            }
        }
    }

    public byte[] getBytes() {
        return (byte[]) this.atr.clone();
    }

    public byte[] getHistoricalBytes() {
        byte[] b = new byte[this.nHistorical];
        System.arraycopy(this.atr, this.startHistorical, b, 0, this.nHistorical);
        return b;
    }

    public String toString() {
        return "ATR: " + this.atr.length + " bytes";
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ATR)) {
            return false;
        }
        return Arrays.equals(this.atr, ((ATR) obj).atr);
    }

    public int hashCode() {
        return Arrays.hashCode(this.atr);
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.atr = (byte[]) in.readUnshared();
        parse();
    }
}
