package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

public final class ObjectIdentifier extends DecoderObject {
    private static final byte RELATIVE_OID = (byte) 13;
    private static final byte TAG_OBJECTID = (byte) 6;
    private byte[] rawValue = null;

    public void checkTag(byte tag) throws Asn1Exception {
        if ((byte) 6 != tag && (byte) 13 != tag) {
            throw new Asn1Exception("Se esperaba un tipo " + HexUtils.hexify(new byte[]{(byte) 6}, false) + " o " + HexUtils.hexify(new byte[]{(byte) 13}, false) + " (" + getClass().getName() + ") " + "pero se encontro un tipo " + HexUtils.hexify(new byte[]{tag}, false));
        }
    }

    protected void decodeValue() throws Asn1Exception, TlvException {
        this.rawValue = new Tlv(getRawDerValue()).getValue();
    }

    protected byte getDefaultTag() {
        return (byte) 6;
    }

    public String toString() {
        if (this.rawValue != null) {
            return OidDictionary.getOidDescription(this.rawValue);
        }
        throw new IllegalStateException("El valor del OID no esta establecido");
    }
}
