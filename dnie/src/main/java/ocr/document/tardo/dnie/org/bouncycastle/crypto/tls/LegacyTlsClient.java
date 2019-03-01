package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class LegacyTlsClient extends DefaultTlsClient {
    protected CertificateVerifyer verifyer;

    public LegacyTlsClient(CertificateVerifyer certificateVerifyer) {
        this.verifyer = certificateVerifyer;
    }

    public TlsAuthentication getAuthentication() throws IOException {
        return new LegacyTlsAuthentication(this.verifyer);
    }
}
