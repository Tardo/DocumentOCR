package org.bouncycastle.crypto.tls;

import org.bouncycastle.asn1.x509.Certificate;

public interface CertificateVerifyer {
    boolean isValid(Certificate[] certificateArr);
}
