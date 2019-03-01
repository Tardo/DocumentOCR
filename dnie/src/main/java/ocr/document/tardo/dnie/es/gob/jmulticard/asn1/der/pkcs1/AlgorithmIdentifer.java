package es.gob.jmulticard.asn1.der.pkcs1;

import es.gob.jmulticard.asn1.der.ObjectIdentifier;
import es.gob.jmulticard.asn1.der.Sequence;

public final class AlgorithmIdentifer extends Sequence {
    public AlgorithmIdentifer() {
        super(new Class[]{ObjectIdentifier.class});
    }
}
