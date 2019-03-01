package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.der.Record;

public final class Dodf extends Record {
    private static final int BUFFER_SIZE = 150;

    public Dodf() {
        super(new Class[]{DataObject.class, DataObject.class, DataObject.class});
    }

    public int getDataObjectCount() {
        return getElementCount();
    }

    public String getDataObjectName(int index) {
        return ((DataObject) getElementAt(index)).getLabel();
    }

    public String getDataObjectPath(int index) {
        return ((DataObject) getElementAt(index)).getDataPath();
    }

    public String toString() {
        StringBuffer sb = new StringBuffer(150);
        sb.append("Fichero de Descripcion de Datos:\n");
        for (int index = 0; index < getDataObjectCount(); index++) {
            sb.append(" Objeto ");
            sb.append(Integer.toString(index));
            sb.append("\n  Nombre del dato: ");
            sb.append(getDataObjectName(index));
            sb.append("\n  Ruta hacia el dato: ");
            sb.append(getDataObjectPath(index));
            sb.append('\n');
        }
        return sb.toString();
    }
}
