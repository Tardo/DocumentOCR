package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.der.Sequence;

abstract class Pkcs15Object extends Sequence {
    Pkcs15Object(Class classAttributes, Class typeAttributes) {
        super(new Class[]{CommonObjectAttributes.class, classAttributes, typeAttributes});
    }

    CommonObjectAttributes getCommonObjectAttributes() {
        return (CommonObjectAttributes) getElementAt(0);
    }

    DecoderObject getClassAttributes() {
        return getElementAt(1);
    }

    DecoderObject getTypeAttributes() {
        return getElementAt(2);
    }
}
