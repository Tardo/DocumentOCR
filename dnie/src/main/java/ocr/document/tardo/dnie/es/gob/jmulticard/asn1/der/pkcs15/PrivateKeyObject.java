package es.gob.jmulticard.asn1.der.pkcs15;

public final class PrivateKeyObject extends Pkcs15Object {
    public PrivateKeyObject() {
        super(CommonKeyAttributes.class, PrivateRsaKeyAttributesContextSpecific.class);
    }

    String getKeyIdentifier() {
        return new String(((CommonKeyAttributes) getClassAttributes()).getIdentifier());
    }

    String getKeyName() {
        return getCommonObjectAttributes().getLabel();
    }

    String getKeyPath() {
        return ((PrivateRsaKeyAttributesContextSpecific) getTypeAttributes()).getPath();
    }

    public String toString() {
        return "Nombre de la clave privada: " + getCommonObjectAttributes().getLabel();
    }
}
