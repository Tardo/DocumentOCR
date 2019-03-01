package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.der.Sequence;
import es.gob.jmulticard.asn1.der.Utf8String;

public final class CommonObjectAttributes extends Sequence {
    public CommonObjectAttributes() {
        super(new Class[]{Utf8String.class, CommonObjectFlags.class});
    }

    public String getLabel() {
        return getElementAt(0).toString();
    }
}
