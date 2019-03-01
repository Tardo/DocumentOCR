package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.der.ContextSpecific;
import java.math.BigInteger;

public final class X509CertificateAttributesContextSpecific extends ContextSpecific {
    private static final byte TAG = (byte) -95;

    public X509CertificateAttributesContextSpecific() {
        super(X509CertificateAttributes.class);
    }

    public void checkTag(byte tag) throws Asn1Exception {
        if (TAG != tag) {
            throw new Asn1Exception("Se esperaba una etiqueta especifica de contexto " + HexUtils.hexify(new byte[]{TAG}, false) + " pero se ha encontrado " + HexUtils.hexify(new byte[]{tag}, false));
        }
    }

    public String toString() {
        return getObject().toString();
    }

    String getIssuer() {
        return ((X509CertificateAttributes) getObject()).getIssuer();
    }

    String getSubject() {
        return ((X509CertificateAttributes) getObject()).getSubject();
    }

    String getPath() {
        return ((X509CertificateAttributes) getObject()).getPath();
    }

    BigInteger getSerialNumber() {
        return ((X509CertificateAttributes) getObject()).getSerialNumber();
    }
}
