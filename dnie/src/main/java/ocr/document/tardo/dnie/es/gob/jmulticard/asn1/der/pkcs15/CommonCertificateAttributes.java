package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.der.OctectString;
import es.gob.jmulticard.asn1.der.Sequence;

public final class CommonCertificateAttributes extends Sequence {
    public CommonCertificateAttributes() {
        super(new Class[]{Identifier.class});
    }

    byte[] getId() {
        if (getElementAt(0) != null) {
            return ((OctectString) getElementAt(0)).getOctectStringByteValue();
        }
        throw new IllegalStateException("No existe el identificador dentro del objeto");
    }

    public String toString() {
        return HexUtils.hexify(getId(), false);
    }
}
