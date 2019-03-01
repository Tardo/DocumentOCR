package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.Digest;

interface TlsHandshakeHash extends Digest {
    TlsHandshakeHash commit();

    TlsHandshakeHash fork();

    void init(TlsContext tlsContext);
}
