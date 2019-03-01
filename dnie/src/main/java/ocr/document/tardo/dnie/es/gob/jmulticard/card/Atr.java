package es.gob.jmulticard.card;

import java.io.Serializable;

public final class Atr implements Serializable {
    private static final long serialVersionUID = 1;
    private final byte[] atrBytes;
    private final byte[] mask;

    public Atr(byte[] a, byte[] m) {
        if (a == null || m == null) {
            throw new IllegalArgumentException("El ATR y su mascara no pueden ser nulos");
        }
        this.atrBytes = new byte[a.length];
        System.arraycopy(a, 0, this.atrBytes, 0, a.length);
        this.mask = new byte[m.length];
        System.arraycopy(m, 0, this.mask, 0, m.length);
    }

    public byte[] getBytes() {
        byte[] tmp = new byte[this.atrBytes.length];
        System.arraycopy(this.atrBytes, 0, tmp, 0, this.atrBytes.length);
        return tmp;
    }

    public boolean equals(Object o) {
        if (!(o instanceof Atr)) {
            return false;
        }
        Atr tmpAtr = (Atr) o;
        if (tmpAtr.getBytes().length != this.atrBytes.length) {
            return false;
        }
        for (int i = 0; i < this.atrBytes.length; i++) {
            if ((this.atrBytes[i] & this.mask[i]) != (tmpAtr.getBytes()[i] & this.mask[i])) {
                return false;
            }
        }
        return true;
    }

    public int hashCode() {
        return hashCode(this.atrBytes) + hashCode(this.mask);
    }

    private static int hashCode(byte[] a) {
        if (a == null) {
            return 0;
        }
        int result = 1;
        for (byte b : a) {
            result = (result * 31) + b;
        }
        return result;
    }
}
