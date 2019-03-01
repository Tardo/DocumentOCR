package es.gob.jmulticard.apdu.connection.cwa14890;

import es.gob.jmulticard.apdu.CommandApdu;

final class CipheredApdu extends CommandApdu {
    private static final byte TAG_CRYPTOGRAPHIC_CHECKSUM = (byte) -114;
    private final byte[] data;
    private final byte[] mac;

    byte[] getMac() {
        byte[] out = new byte[this.mac.length];
        System.arraycopy(this.mac, 0, out, 0, this.mac.length);
        return out;
    }

    byte[] getCryptogramData() {
        byte[] out = new byte[this.data.length];
        System.arraycopy(this.data, 0, out, 0, this.data.length);
        return out;
    }

    CipheredApdu(byte cla, byte ins, byte p1, byte p2, byte[] data, byte[] mac) {
        super(cla, ins, p1, p2, buildData(data, mac), null);
        this.mac = new byte[mac.length];
        System.arraycopy(mac, 0, this.mac, 0, mac.length);
        this.data = new byte[data.length];
        System.arraycopy(data, 0, this.data, 0, data.length);
    }

    private static byte[] buildData(byte[] data, byte[] mac) {
        if (data == null || mac == null) {
            throw new IllegalArgumentException("Ni los datos (TLV) ni el MAC pueden ser nulos");
        } else if (mac.length == 4 || mac.length == 8) {
            byte[] ret = new byte[((data.length + mac.length) + 2)];
            if (data.length > 0) {
                System.arraycopy(data, 0, ret, 0, data.length);
            }
            ret[ret.length - (mac.length + 2)] = TAG_CRYPTOGRAPHIC_CHECKSUM;
            ret[ret.length - (mac.length + 1)] = (byte) mac.length;
            for (int idx = 1; idx <= mac.length; idx++) {
                ret[ret.length - idx] = mac[mac.length - idx];
            }
            return ret;
        } else {
            throw new IllegalArgumentException("El MAC debe medir exactamente cuatro/ocho octetos");
        }
    }

    public void setLe(int le) {
        throw new UnsupportedOperationException("No se puede establecer el Le en una APDU cifrada");
    }
}
