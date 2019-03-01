package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.der.DerInteger;

public class Reference extends DerInteger {
    public int getItValue() {
        return getIntegerValue().intValue();
    }
}
