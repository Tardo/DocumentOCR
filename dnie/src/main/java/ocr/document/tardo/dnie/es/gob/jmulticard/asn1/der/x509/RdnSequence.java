package es.gob.jmulticard.asn1.der.x509;

import es.gob.jmulticard.asn1.der.SequenceOf;

public final class RdnSequence extends SequenceOf {
    public RdnSequence() {
        super(RelativeDistinguishedName.class);
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        int lastIndex = getElementCount();
        for (int i = 0; i < lastIndex; i++) {
            sb.append(getElementAt(i));
            if (i != lastIndex - 1) {
                sb.append(", ");
            }
        }
        return sb.toString();
    }
}
