package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

public abstract class BitString extends DecoderObject {
    private static final byte TAG_BITSTRING = (byte) 3;

    protected void decodeValue() throws Asn1Exception, TlvException {
        if ((byte) 3 != new Tlv(getRawDerValue()).getTag()) {
            throw new Asn1Exception("Se esperaba un TLV de tipo BitString pero se ha encontrado uno de tipo " + HexUtils.hexify(new byte[]{tlv.getTag()}, false));
        }
    }

    protected byte getDefaultTag() {
        return (byte) 3;
    }
}
