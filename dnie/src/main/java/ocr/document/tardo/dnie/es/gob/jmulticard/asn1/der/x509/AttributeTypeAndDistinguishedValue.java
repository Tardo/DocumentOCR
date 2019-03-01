package es.gob.jmulticard.asn1.der.x509;

import es.gob.jmulticard.asn1.der.ObjectIdentifier;
import es.gob.jmulticard.asn1.der.Sequence;
import es.gob.jmulticard.asn1.der.Utf8String;

public final class AttributeTypeAndDistinguishedValue extends Sequence {
    public AttributeTypeAndDistinguishedValue() {
        super(new Class[]{ObjectIdentifier.class, Utf8String.class});
    }

    public String toString() {
        return getElementAt(0).toString() + "=\"" + getElementAt(1).toString() + "\"";
    }
}
