package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.der.Sequence;
import es.gob.jmulticard.asn1.der.Utf8String;

public final class CommonDataObjectAttributes extends Sequence {
    public CommonDataObjectAttributes() {
        super(new Class[]{Utf8String.class});
    }

    public String getApplicationName() {
        return getElementAt(0).toString();
    }

    public byte[] getIdentifier() {
        return ((Identifier) getElementAt(1)).getOctectStringByteValue();
    }
}
