package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

public class DerBoolean extends DecoderObject {
    private static final byte TAG_BOOLEAN = (byte) 1;
    private Boolean booleanValue = null;

    protected void decodeValue() throws Asn1Exception, TlvException {
        boolean z = false;
        Tlv tmpTlv = new Tlv(getRawDerValue());
        checkTag(tmpTlv.getTag());
        if (tmpTlv.getValue()[0] == (byte) 0) {
            z = true;
        }
        this.booleanValue = Boolean.valueOf(z);
    }

    protected byte getDefaultTag() {
        return (byte) 1;
    }

    public boolean getBooleanValue() {
        if (this.booleanValue != null) {
            return this.booleanValue.booleanValue();
        }
        throw new IllegalStateException("El valor del objeto boolean no esta establecido");
    }
}
