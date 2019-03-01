package es.gob.jmulticard.asn1.der;

public abstract class Set extends Sequence {
    private static final byte TAG_SET = (byte) 49;

    protected Set(Class[] types) {
        super(types);
    }

    protected byte getDefaultTag() {
        return TAG_SET;
    }
}
