package org.bouncycastle.cert.jcajce;

import java.io.IOException;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.x509.X509AttributeCertificate;

public class JcaX509AttributeCertificateHolder extends X509AttributeCertificateHolder {
    public JcaX509AttributeCertificateHolder(X509AttributeCertificate x509AttributeCertificate) throws IOException {
        super(AttributeCertificate.getInstance(x509AttributeCertificate.getEncoded()));
    }
}
