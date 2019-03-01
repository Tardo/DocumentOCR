package org.bouncycastle.crypto.tls;

import org.bouncycastle.asn1.x509.Certificate;

public class AlwaysValidVerifyer implements CertificateVerifyer {
    public boolean isValid(Certificate[] certificateArr) {
        return true;
    }
}
