package es.gob.jmulticard.apdu;

public class Apdu {
    private byte[] apduBytes = null;

    public byte[] getBytes() {
        byte[] response = new byte[this.apduBytes.length];
        System.arraycopy(this.apduBytes, 0, response, 0, this.apduBytes.length);
        return response;
    }

    protected void setBytes(byte[] apdu) {
        this.apduBytes = new byte[apdu.length];
        System.arraycopy(apdu, 0, this.apduBytes, 0, apdu.length);
    }

    protected Apdu() {
    }
}
