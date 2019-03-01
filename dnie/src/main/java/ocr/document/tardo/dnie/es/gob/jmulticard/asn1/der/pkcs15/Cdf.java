package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.der.Record;
import java.math.BigInteger;

public final class Cdf extends Record {
    private static final int BUFFER_SIZE = 150;

    public Cdf() {
        super(new Class[]{CertificateObject.class, CertificateObject.class, CertificateObject.class});
    }

    public int getCertificateCount() {
        return getElementCount();
    }

    public String getCertificateIssuerPrincipal(int index) {
        return ((CertificateObject) getElementAt(index)).getIssuer();
    }

    public String getCertificateSubjectPrincipal(int index) {
        return ((CertificateObject) getElementAt(index)).getSubject();
    }

    public BigInteger getCertificateSerialNumber(int index) {
        return ((CertificateObject) getElementAt(index)).getSerialNumber();
    }

    public byte[] getCertificateIdentifier(int index) {
        return ((CertificateObject) getElementAt(index)).getIdentifier();
    }

    public String getCertificatePath(int index) {
        return ((CertificateObject) getElementAt(index)).getPath();
    }

    public String getCertificateAlias(int index) {
        return ((CertificateObject) getElementAt(index)).getAlias();
    }

    public String toString() {
        StringBuffer sb = new StringBuffer(150);
        sb.append("Fichero de Descripcion de Certificados:\n");
        for (int index = 0; index < getCertificateCount(); index++) {
            sb.append(" Certificado ");
            sb.append(Integer.toString(index));
            sb.append("\n  Alias: ");
            sb.append(getCertificateAlias(index));
            sb.append("\n  Titular: ");
            sb.append(getCertificateSubjectPrincipal(index));
            sb.append("\n  Emisor: ");
            sb.append(getCertificateIssuerPrincipal(index));
            sb.append("\n  Numero de serie: ");
            sb.append(getCertificateSerialNumber(index).toString());
            sb.append("\n  Identificador: ");
            sb.append(HexUtils.hexify(getCertificateIdentifier(index), true));
            sb.append("\n  Ruta PKCS#15: ");
            sb.append(getCertificatePath(index));
            sb.append('\n');
        }
        return sb.toString();
    }
}
