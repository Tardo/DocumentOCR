package org.bouncycastle.crypto.tls;

import java.io.IOException;

public abstract class PSKTlsClient extends AbstractTlsClient {
    protected TlsPSKIdentity pskIdentity;

    public PSKTlsClient(TlsCipherFactory tlsCipherFactory, TlsPSKIdentity tlsPSKIdentity) {
        super(tlsCipherFactory);
        this.pskIdentity = tlsPSKIdentity;
    }

    public PSKTlsClient(TlsPSKIdentity tlsPSKIdentity) {
        this.pskIdentity = tlsPSKIdentity;
    }

    protected TlsKeyExchange createPSKKeyExchange(int i) {
        return new TlsPSKKeyExchange(i, this.supportedSignatureAlgorithms, this.pskIdentity);
    }

    public TlsCipher getCipher() throws IOException {
        switch (this.selectedCipherSuite) {
            case 44:
            case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA /*45*/:
            case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA /*46*/:
                return this.cipherFactory.createCipher(this.context, 0, 2);
            case 138:
            case 142:
            case 146:
                return this.cipherFactory.createCipher(this.context, 2, 2);
            case 139:
            case 143:
            case 147:
                return this.cipherFactory.createCipher(this.context, 7, 2);
            case 140:
            case 144:
            case 148:
                return this.cipherFactory.createCipher(this.context, 8, 2);
            case 141:
            case 145:
            case 149:
                return this.cipherFactory.createCipher(this.context, 9, 2);
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    public int[] getCipherSuites() {
        return new int[]{145, 144, 143, 142, 149, 148, 147, 146, 141, 140, 139, 138};
    }

    public TlsKeyExchange getKeyExchange() throws IOException {
        switch (this.selectedCipherSuite) {
            case 44:
            case 138:
            case 139:
            case 140:
            case 141:
                return createPSKKeyExchange(13);
            case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA /*45*/:
            case 142:
            case 143:
            case 144:
            case 145:
                return createPSKKeyExchange(14);
            case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA /*46*/:
            case 146:
            case 147:
            case 148:
            case 149:
                return createPSKKeyExchange(15);
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }
}
