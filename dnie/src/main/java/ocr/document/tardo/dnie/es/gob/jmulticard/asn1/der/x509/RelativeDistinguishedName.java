package es.gob.jmulticard.asn1.der.x509;

import es.gob.jmulticard.asn1.der.Set;

public final class RelativeDistinguishedName extends Set {
    public RelativeDistinguishedName() {
        super(new Class[]{AttributeTypeAndDistinguishedValue.class});
    }

    public String toString() {
        return getElementAt(0).toString();
    }
}
