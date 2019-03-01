package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.der.DerInteger;
import es.gob.jmulticard.asn1.der.OctectString;
import es.gob.jmulticard.asn1.der.Sequence;

public final class Path extends Sequence {
    public Path() {
        super(new Class[]{OctectString.class, DerInteger.class, PathLength.class});
    }

    String getPathString() {
        return HexUtils.hexify(((OctectString) getElementAt(0)).getOctectStringByteValue(), false);
    }
}
