package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.der.DerInteger;
import es.gob.jmulticard.asn1.der.Sequence;

public final class PrivateRsaKeyAttributes extends Sequence {
    public PrivateRsaKeyAttributes() {
        super(new Class[]{Path.class, DerInteger.class});
    }

    String getPath() {
        return ((Path) getElementAt(0)).getPathString();
    }
}
