package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.ContextSpecific;
import es.gob.jmulticard.asn1.der.Record;

public final class PathLength extends ContextSpecific {
    private static final byte TAG = Byte.MIN_VALUE;
    private Integer value = null;

    int getIntValue() {
        return this.value.intValue();
    }

    public PathLength() {
        super(Record.class);
    }

    protected void decodeValue() throws Asn1Exception, TlvException {
        this.value = Integer.valueOf(String.valueOf(HexUtils.getUnsignedInt(new Tlv(getRawDerValue()).getValue(), 0)));
    }

    public void checkTag(byte tag) throws Asn1Exception {
        if (TAG != tag) {
            throw new Asn1Exception("Se esperaba una etiqueta especifica de contexto " + HexUtils.hexify(new byte[]{TAG}, false) + " pero se ha encontrado " + HexUtils.hexify(new byte[]{tag}, false));
        }
    }
}
