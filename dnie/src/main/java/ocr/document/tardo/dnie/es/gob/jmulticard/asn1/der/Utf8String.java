package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;
import java.io.UnsupportedEncodingException;

public final class Utf8String extends DecoderObject {
    private static final byte TAG_PRINTABLESTRING = (byte) 19;
    private static final byte TAG_UTF8STRING = (byte) 12;
    private String stringValue = null;

    protected byte getDefaultTag() {
        return (byte) 12;
    }

    public void checkTag(byte tag) throws Asn1Exception {
        if ((byte) 12 != tag && TAG_PRINTABLESTRING != tag) {
            throw new Asn1Exception("Se esperaba un tipo " + HexUtils.hexify(new byte[]{TAG_PRINTABLESTRING}, false) + " o " + HexUtils.hexify(new byte[]{TAG_PRINTABLESTRING}, false) + " (" + getClass().getName() + ") " + "pero se encontro un tipo " + HexUtils.hexify(new byte[]{tag}, false));
        }
    }

    protected void decodeValue() throws Asn1Exception, TlvException {
        Tlv tlv = new Tlv(getRawDerValue());
        checkTag(tlv.getTag());
        try {
            this.stringValue = new String(tlv.getValue(), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new Asn1Exception("No se soporta la codificacion UFT8 en el entorno de ejecucion: " + e, e);
        }
    }

    public String toString() {
        return this.stringValue;
    }
}
