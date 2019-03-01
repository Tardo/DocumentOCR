package es.gob.jmulticard.asn1;

import es.gob.jmulticard.HexUtils;

public abstract class DecoderObject {
    private byte[] rawDerValue = null;

    protected abstract void decodeValue() throws Asn1Exception, TlvException;

    protected abstract byte getDefaultTag();

    protected byte[] getRawDerValue() {
        byte[] out = new byte[this.rawDerValue.length];
        System.arraycopy(this.rawDerValue, 0, out, 0, this.rawDerValue.length);
        return out;
    }

    public void setDerValue(byte[] value) throws Asn1Exception, TlvException {
        if (value == null) {
            throw new IllegalArgumentException("El valor del objeto ASN.1 no puede ser nulo");
        }
        this.rawDerValue = new byte[value.length];
        System.arraycopy(value, 0, this.rawDerValue, 0, value.length);
        decodeValue();
    }

    public byte[] getBytes() {
        byte[] out = new byte[this.rawDerValue.length];
        System.arraycopy(this.rawDerValue, 0, out, 0, this.rawDerValue.length);
        return out;
    }

    public void checkTag(byte tag) throws Asn1Exception {
        if (getDefaultTag() != tag) {
            throw new Asn1Exception("Se esperaba un tipo " + HexUtils.hexify(new byte[]{getDefaultTag()}, false) + " (" + getClass().getName() + ") " + "pero se encontro un tipo " + HexUtils.hexify(new byte[]{tag}, false));
        }
    }
}
