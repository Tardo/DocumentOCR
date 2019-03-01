package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.der.DerInteger;
import es.gob.jmulticard.asn1.der.Sequence;
import es.gob.jmulticard.asn1.der.x509.RdnSequence;
import java.math.BigInteger;

public final class X509CertificateAttributes extends Sequence {
    public X509CertificateAttributes() {
        super(new Class[]{Path.class, RdnSequence.class, CertificateIssuerContextSpecific.class, DerInteger.class});
    }

    String getIssuer() {
        return getElementAt(2).toString();
    }

    String getSubject() {
        return getElementAt(1).toString();
    }

    String getPath() {
        return ((Path) getElementAt(0)).getPathString();
    }

    BigInteger getSerialNumber() {
        return ((DerInteger) getElementAt(3)).getIntegerValue();
    }

    public String toString() {
        return "Atributos del certificado\n Ruta: " + getPath() + "\n" + " Titular: " + getSubject() + "\n" + " Emisor: " + getIssuer() + "\n" + " Numero de serie: " + getSerialNumber().toString();
    }
}
