package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;
import java.util.Vector;

public abstract class SequenceOf extends DecoderObject {
    private static final byte TAG_SEQUENCE = (byte) 48;
    private final Class elementsType;
    private Vector sequenceObjects = null;

    protected void decodeValue() throws Asn1Exception, TlvException {
        Tlv tlv = new Tlv(getRawDerValue());
        checkTag(tlv.getTag());
        int offset = 0;
        byte[] valueBytes = tlv.getValue();
        this.sequenceObjects = new Vector();
        while (offset < valueBytes.length) {
            byte[] remainingBytes = new byte[(valueBytes.length - offset)];
            System.arraycopy(valueBytes, offset, remainingBytes, 0, remainingBytes.length);
            tlv = new Tlv(remainingBytes);
            try {
                DecoderObject tmpDo = (DecoderObject) this.elementsType.newInstance();
                offset += tlv.getBytes().length;
                tmpDo.checkTag(tlv.getTag());
                tmpDo.setDerValue(tlv.getBytes());
                this.sequenceObjects.addElement(tmpDo);
            } catch (Exception e) {
                throw new Asn1Exception("No se ha podido instanciar un " + this.elementsType.getName() + " en la secuencia: " + e, e);
            }
        }
    }

    protected SequenceOf(Class type) {
        if (type == null) {
            throw new IllegalArgumentException();
        }
        this.elementsType = type;
    }

    protected byte getDefaultTag() {
        return TAG_SEQUENCE;
    }

    protected DecoderObject getElementAt(int index) {
        return (DecoderObject) this.sequenceObjects.elementAt(index);
    }

    protected int getElementCount() {
        return this.sequenceObjects.size();
    }
}
