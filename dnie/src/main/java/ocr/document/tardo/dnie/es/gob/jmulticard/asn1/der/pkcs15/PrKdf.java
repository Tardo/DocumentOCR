package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.der.Record;

public final class PrKdf extends Record {
    private static final int BUFFER_SIZE = 150;

    public PrKdf() {
        super(new Class[]{PrivateKeyObject.class, PrivateKeyObject.class});
    }

    public int getKeyCount() {
        return getElementCount();
    }

    public String getKeyIdentifier(int index) {
        return ((PrivateKeyObject) getElementAt(index)).getKeyIdentifier();
    }

    public String getKeyName(int index) {
        return ((PrivateKeyObject) getElementAt(index)).getKeyName();
    }

    public String getKeyPath(int index) {
        return ((PrivateKeyObject) getElementAt(index)).getKeyPath();
    }

    public String toString() {
        StringBuffer sb = new StringBuffer(150);
        sb.append("Fichero de Descripcion de Claves Privadas:\n");
        for (int index = 0; index < getKeyCount(); index++) {
            sb.append(" Clave privada ");
            sb.append(Integer.toString(index));
            sb.append("\n  Nombre de la clave: ");
            sb.append(getKeyName(index));
            sb.append("\n  Ruta hacia la clave: ");
            sb.append(getKeyPath(index));
            sb.append('\n');
        }
        return sb.toString();
    }
}
