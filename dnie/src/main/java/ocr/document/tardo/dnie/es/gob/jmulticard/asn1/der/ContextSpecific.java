package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

public abstract class ContextSpecific extends DecoderObject {
    private final Class elementType;
    private DecoderObject object = null;

    protected DecoderObject getObject() {
        if (this.object != null) {
            return this.object;
        }
        throw new IllegalStateException();
    }

    protected void decodeValue() throws Asn1Exception, TlvException {
        try {
            DecoderObject tmpDo = (DecoderObject) this.elementType.newInstance();
            tmpDo.setDerValue(new Tlv(getRawDerValue()).getValue());
            this.object = tmpDo;
        } catch (Exception e) {
            throw new Asn1Exception("No se ha podido instanciar un " + this.elementType.getName() + " en el contexto especifico: " + e, e);
        }
    }

    public ContextSpecific(Class type) {
        if (type == null) {
            throw new IllegalArgumentException("El tipo contenido dentro de ContextSpecific no puede ser nulo");
        }
        this.elementType = type;
    }

    protected byte getDefaultTag() {
        throw new UnsupportedOperationException("No hay tipo por defecto");
    }

    public void checkTag(byte tag) throws Asn1Exception {
        if ((tag & 192) != 128) {
            throw new Asn1Exception("La etiqueta " + HexUtils.hexify(new byte[]{tag}, false) + " no es valida para un objeto especifico del contexto");
        }
    }
}
