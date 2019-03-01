package es.gob.jmulticard.asn1.der.pkcs15;

public final class DataObject extends Pkcs15Object {
    public DataObject() {
        super(CommonDataObjectAttributes.class, DataObjectAttributesContextSpecific.class);
    }

    String getDataPath() {
        return ((DataObjectAttributesContextSpecific) getTypeAttributes()).getPath();
    }

    byte[] getIdentifier() {
        return ((CommonDataObjectAttributes) getClassAttributes()).getIdentifier();
    }

    String getLabel() {
        return getCommonObjectAttributes().getLabel();
    }

    public String toString() {
        return getTypeAttributes().toString() + "\nAlias del dato: " + getCommonObjectAttributes().getLabel() + "\nIdentificador del dato: " + getClassAttributes().toString();
    }
}
