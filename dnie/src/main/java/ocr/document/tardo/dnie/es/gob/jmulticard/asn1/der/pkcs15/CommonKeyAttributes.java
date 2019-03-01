package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.der.DerBoolean;
import es.gob.jmulticard.asn1.der.Sequence;

public final class CommonKeyAttributes extends Sequence {
    public CommonKeyAttributes() {
        super(new Class[]{Identifier.class, KeyUsageFlags.class, DerBoolean.class, AccessFlags.class, Reference.class});
    }

    public byte[] getIdentifier() {
        return ((Identifier) getElementAt(0)).getOctectStringByteValue();
    }
}
