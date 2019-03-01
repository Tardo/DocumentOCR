package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;
import java.math.BigInteger;

public class DerInteger extends DecoderObject {
    private static final byte TAG_INTEGER = (byte) 2;
    private BigInteger value = null;

    protected void decodeValue() throws Asn1Exception, TlvException {
        this.value = new BigInteger(new Tlv(getRawDerValue()).getValue());
    }

    public BigInteger getIntegerValue() {
        if (this.value != null) {
            return this.value;
        }
        throw new IllegalStateException("El valor del objeto aun no esta establecido");
    }

    protected byte getDefaultTag() {
        return (byte) 2;
    }
}
