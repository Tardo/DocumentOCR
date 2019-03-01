package org.bouncycastle.crypto.tls;

import java.io.IOException;
import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.params.DHParameters;

public abstract class DefaultTlsServer extends AbstractTlsServer {
    public DefaultTlsServer(TlsCipherFactory tlsCipherFactory) {
        super(tlsCipherFactory);
    }

    protected TlsKeyExchange createDHEKeyExchange(int i) {
        return new TlsDHEKeyExchange(i, this.supportedSignatureAlgorithms, getDHParameters());
    }

    protected TlsKeyExchange createDHKeyExchange(int i) {
        return new TlsDHKeyExchange(i, this.supportedSignatureAlgorithms, getDHParameters());
    }

    protected TlsKeyExchange createECDHEKeyExchange(int i) {
        return new TlsECDHEKeyExchange(i, this.supportedSignatureAlgorithms, this.namedCurves, this.clientECPointFormats, this.serverECPointFormats);
    }

    protected TlsKeyExchange createECDHKeyExchange(int i) {
        return new TlsECDHKeyExchange(i, this.supportedSignatureAlgorithms, this.namedCurves, this.clientECPointFormats, this.serverECPointFormats);
    }

    protected TlsKeyExchange createRSAKeyExchange() {
        return new TlsRSAKeyExchange(this.supportedSignatureAlgorithms);
    }

    public TlsCipher getCipher() throws IOException {
        switch (this.selectedCipherSuite) {
            case 1:
                return this.cipherFactory.createCipher(this.context, 0, 1);
            case 2:
            case 49153:
            case 49158:
            case 49163:
            case 49168:
                return this.cipherFactory.createCipher(this.context, 0, 2);
            case 4:
                return this.cipherFactory.createCipher(this.context, 2, 1);
            case 5:
            case 49154:
            case 49159:
            case 49164:
            case 49169:
                return this.cipherFactory.createCipher(this.context, 2, 2);
            case 10:
            case 13:
            case 16:
            case 19:
            case 22:
            case 49155:
            case 49160:
            case 49165:
            case 49170:
                return this.cipherFactory.createCipher(this.context, 7, 2);
            case 47:
            case 48:
            case 49:
            case 50:
            case 51:
            case 49156:
            case 49161:
            case 49166:
            case 49171:
                return this.cipherFactory.createCipher(this.context, 8, 2);
            case 53:
            case 54:
            case 55:
            case 56:
            case 57:
            case 49157:
            case 49162:
            case 49167:
            case 49172:
                return this.cipherFactory.createCipher(this.context, 9, 2);
            case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                return this.cipherFactory.createCipher(this.context, 0, 3);
            case 60:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 /*62*/:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256 /*63*/:
            case 64:
            case 103:
            case 49187:
            case 49189:
            case 49191:
            case 49193:
                return this.cipherFactory.createCipher(this.context, 8, 3);
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 /*61*/:
            case 104:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256 /*105*/:
            case 106:
            case 107:
                return this.cipherFactory.createCipher(this.context, 9, 3);
            case 65:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA /*66*/:
            case 67:
            case 68:
            case 69:
                return this.cipherFactory.createCipher(this.context, 12, 2);
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA /*132*/:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA /*133*/:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA /*134*/:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA /*135*/:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA /*136*/:
                return this.cipherFactory.createCipher(this.context, 13, 2);
            case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA /*150*/:
            case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA /*151*/:
            case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA /*152*/:
            case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA /*153*/:
            case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA /*154*/:
                return this.cipherFactory.createCipher(this.context, 14, 2);
            case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 /*156*/:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 /*158*/:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256 /*160*/:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 /*162*/:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256 /*164*/:
            case 49195:
            case 49197:
            case 49199:
            case 49201:
                return this.cipherFactory.createCipher(this.context, 10, 0);
            case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384 /*157*/:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 /*159*/:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384 /*161*/:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 /*163*/:
            case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384 /*165*/:
            case 49196:
            case 49198:
            case 49200:
            case 49202:
                return this.cipherFactory.createCipher(this.context, 11, 0);
            case 49188:
            case 49190:
            case 49192:
            case 49194:
                return this.cipherFactory.createCipher(this.context, 9, 4);
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    protected int[] getCipherSuites() {
        return new int[]{49172, 49171, 49170, 57, 51, 22, 53, 47, 10};
    }

    public TlsCredentials getCredentials() throws IOException {
        switch (this.selectedCipherSuite) {
            case 1:
            case 2:
            case 4:
            case 5:
            case 10:
            case 47:
            case 53:
            case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
            case 60:
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 /*61*/:
            case 65:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA /*132*/:
            case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA /*150*/:
            case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 /*156*/:
            case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384 /*157*/:
                return getRSAEncryptionCredentials();
            case 22:
            case 51:
            case 57:
            case 69:
            case 103:
            case 107:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA /*136*/:
            case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA /*154*/:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 /*158*/:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 /*159*/:
            case 49170:
            case 49171:
            case 49172:
            case 49191:
            case 49192:
            case 49199:
            case 49200:
                return getRSASignerCredentials();
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    protected DHParameters getDHParameters() {
        return DHStandardGroups.rfc5114_1024_160;
    }

    public TlsKeyExchange getKeyExchange() throws IOException {
        switch (this.selectedCipherSuite) {
            case 1:
            case 2:
            case 4:
            case 5:
            case 10:
            case 47:
            case 53:
            case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
            case 60:
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 /*61*/:
            case 65:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA /*132*/:
            case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA /*150*/:
            case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 /*156*/:
            case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384 /*157*/:
                return createRSAKeyExchange();
            case 13:
            case 48:
            case 54:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 /*62*/:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA /*66*/:
            case 104:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA /*133*/:
            case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA /*151*/:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256 /*164*/:
            case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384 /*165*/:
                return createDHKeyExchange(7);
            case 16:
            case 49:
            case 55:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256 /*63*/:
            case 67:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256 /*105*/:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA /*134*/:
            case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA /*152*/:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256 /*160*/:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384 /*161*/:
                return createDHKeyExchange(9);
            case 19:
            case 50:
            case 56:
            case 64:
            case 68:
            case 106:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA /*135*/:
            case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA /*153*/:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 /*162*/:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 /*163*/:
                return createDHEKeyExchange(3);
            case 22:
            case 51:
            case 57:
            case 69:
            case 103:
            case 107:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA /*136*/:
            case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA /*154*/:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 /*158*/:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 /*159*/:
                return createDHEKeyExchange(5);
            case 49153:
            case 49154:
            case 49155:
            case 49156:
            case 49157:
            case 49189:
            case 49190:
            case 49197:
            case 49198:
                return createECDHKeyExchange(16);
            case 49158:
            case 49159:
            case 49160:
            case 49161:
            case 49162:
            case 49187:
            case 49188:
            case 49195:
            case 49196:
                return createECDHEKeyExchange(17);
            case 49163:
            case 49164:
            case 49165:
            case 49166:
            case 49167:
            case 49193:
            case 49194:
            case 49201:
            case 49202:
                return createECDHKeyExchange(18);
            case 49168:
            case 49169:
            case 49170:
            case 49171:
            case 49172:
            case 49191:
            case 49192:
            case 49199:
            case 49200:
                return createECDHEKeyExchange(19);
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }
}
