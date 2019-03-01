package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

public abstract class Sequence extends DecoderObject {
    private static final byte TAG_SEQUENCE = (byte) 48;
    private final DecoderObject[] elements;
    private final Class[] elementsTypes;

    protected Sequence(Class[] types) {
        if (types == null) {
            throw new IllegalArgumentException();
        }
        this.elementsTypes = new Class[types.length];
        System.arraycopy(types, 0, this.elementsTypes, 0, types.length);
        this.elements = new DecoderObject[types.length];
    }

    protected void decodeValue() throws Asn1Exception, TlvException {
        Tlv mainTlv = new Tlv(getRawDerValue());
        checkTag(mainTlv.getTag());
        int offset = 0;
        byte[] rawValue = mainTlv.getValue();
        int i = 0;
        while (i < this.elementsTypes.length) {
            byte[] remainingBytes = new byte[(rawValue.length - offset)];
            System.arraycopy(rawValue, offset, remainingBytes, 0, remainingBytes.length);
            Tlv tlv = new Tlv(remainingBytes);
            try {
                DecoderObject tmpDo = (DecoderObject) this.elementsTypes[i].newInstance();
                tmpDo.checkTag(tlv.getTag());
                tmpDo.setDerValue(tlv.getBytes());
                offset += tlv.getBytes().length;
                this.elements[i] = tmpDo;
                i++;
            } catch (Exception e) {
                throw new Asn1Exception("No se ha podido instanciar un " + this.elementsTypes[i].getName() + " en la posicion " + Integer.toString(i) + " de la secuencia: " + e, e);
            }
        }
    }

    protected byte getDefaultTag() {
        return TAG_SEQUENCE;
    }

    protected DecoderObject getElementAt(int index) {
        return this.elements[index];
    }
}
