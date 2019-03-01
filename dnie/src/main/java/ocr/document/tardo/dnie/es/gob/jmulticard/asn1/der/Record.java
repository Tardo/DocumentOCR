package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

public abstract class Record extends DecoderObject {
    private final DecoderObject[] elements;
    private final Class[] elementsTypes;

    protected Record(Class[] types) {
        if (types == null || types.length == 0) {
            throw new IllegalArgumentException("Los tipos de los elementos del registro no pueden ser nulos ni vacios");
        }
        this.elementsTypes = new Class[types.length];
        System.arraycopy(types, 0, this.elementsTypes, 0, types.length);
        this.elements = new DecoderObject[types.length];
    }

    protected int getElementCount() {
        return this.elements.length;
    }

    protected DecoderObject getElementAt(int pos) {
        if (pos >= 0 && pos < this.elements.length) {
            return this.elements[pos];
        }
        throw new IndexOutOfBoundsException("No existe un elemento en este registro en el indice " + Integer.toString(pos));
    }

    protected void decodeValue() throws Asn1Exception, TlvException {
        if (getRawDerValue().length == 0) {
            throw new Asn1Exception("El valor del objeto ASN.1 esta vacio");
        }
        int offset = 0;
        int i = 0;
        while (i < this.elementsTypes.length) {
            byte[] remainingBytes = new byte[(getRawDerValue().length - offset)];
            System.arraycopy(getRawDerValue(), offset, remainingBytes, 0, remainingBytes.length);
            Tlv tlv = new Tlv(remainingBytes);
            try {
                DecoderObject tmpDo = (DecoderObject) this.elementsTypes[i].newInstance();
                tmpDo.checkTag(tlv.getTag());
                offset += tlv.getBytes().length;
                tmpDo.setDerValue(tlv.getBytes());
                this.elements[i] = tmpDo;
                i++;
            } catch (Exception e) {
                throw new Asn1Exception("No se ha podido instanciar un " + this.elementsTypes[i].getName() + " en la posicion " + Integer.toString(i) + " del registro: " + e, e);
            }
        }
    }

    protected byte getDefaultTag() {
        throw new UnsupportedOperationException("No hay tipo por defecto");
    }
}
