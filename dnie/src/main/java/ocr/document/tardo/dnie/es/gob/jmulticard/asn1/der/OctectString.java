package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

public class OctectString extends DecoderObject {
    private static final byte TAG_OCTECTSTRING = (byte) 4;
    private byte[] value = null;

    protected void decodeValue() throws Asn1Exception, TlvException {
        Tlv tlv = new Tlv(getRawDerValue());
        if ((byte) 4 != tlv.getTag()) {
            throw new TlvException("Se esperaba un TLV de tipo OctectString pero se ha encontrado uno de tipo " + HexUtils.hexify(new byte[]{tlv.getTag()}, false));
        }
        this.value = tlv.getValue();
    }

    protected byte getDefaultTag() {
        return (byte) 4;
    }

    public byte[] getOctectStringByteValue() {
        byte[] out = new byte[this.value.length];
        System.arraycopy(this.value, 0, out, 0, this.value.length);
        return out;
    }
}
