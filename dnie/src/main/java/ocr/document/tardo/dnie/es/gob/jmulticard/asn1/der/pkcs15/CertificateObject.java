package es.gob.jmulticard.asn1.der.pkcs15;

import java.math.BigInteger;

public final class CertificateObject extends Pkcs15Object {
    public CertificateObject() {
        super(CommonCertificateAttributes.class, X509CertificateAttributesContextSpecific.class);
    }

    String getIssuer() {
        return ((X509CertificateAttributesContextSpecific) getTypeAttributes()).getIssuer();
    }

    String getSubject() {
        return ((X509CertificateAttributesContextSpecific) getTypeAttributes()).getSubject();
    }

    String getPath() {
        return ((X509CertificateAttributesContextSpecific) getTypeAttributes()).getPath();
    }

    BigInteger getSerialNumber() {
        return ((X509CertificateAttributesContextSpecific) getTypeAttributes()).getSerialNumber();
    }

    byte[] getIdentifier() {
        return ((CommonCertificateAttributes) getClassAttributes()).getId();
    }

    String getAlias() {
        return getCommonObjectAttributes().getLabel();
    }

    public String toString() {
        return getTypeAttributes().toString() + "\nAlias del certificado: " + getCommonObjectAttributes().getLabel() + "\nIdentificador del certificado: " + getClassAttributes().toString();
    }
}
