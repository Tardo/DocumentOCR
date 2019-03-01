package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class LegacyTlsAuthentication extends ServerOnlyTlsAuthentication {
    protected CertificateVerifyer verifyer;

    public LegacyTlsAuthentication(CertificateVerifyer certificateVerifyer) {
        this.verifyer = certificateVerifyer;
    }

    public void notifyServerCertificate(Certificate certificate) throws IOException {
        if (!this.verifyer.isValid(certificate.getCertificateList())) {
            throw new TlsFatalAlert((short) 90);
        }
    }
}
