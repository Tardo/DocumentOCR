package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Vector;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.io.SignerInputStream;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.BigIntegers;

public class TlsSRPKeyExchange extends AbstractTlsKeyExchange {
    /* renamed from: B */
    protected BigInteger f501B = null;
    protected byte[] identity;
    protected byte[] password;
    /* renamed from: s */
    protected byte[] f502s = null;
    protected AsymmetricKeyParameter serverPublicKey = null;
    protected SRP6Client srpClient = new SRP6Client();
    protected TlsSigner tlsSigner;

    public TlsSRPKeyExchange(int i, Vector vector, byte[] bArr, byte[] bArr2) {
        super(i, vector);
        switch (i) {
            case 21:
                this.tlsSigner = null;
                break;
            case 22:
                this.tlsSigner = new TlsDSSSigner();
                break;
            case 23:
                this.tlsSigner = new TlsRSASigner();
                break;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
        this.keyExchange = i;
        this.identity = bArr;
        this.password = bArr2;
    }

    public void generateClientKeyExchange(OutputStream outputStream) throws IOException {
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(this.srpClient.generateClientCredentials(this.f502s, this.identity, this.password)), outputStream);
    }

    public byte[] generatePremasterSecret() throws IOException {
        try {
            return BigIntegers.asUnsignedByteArray(this.srpClient.calculateSecret(this.f501B));
        } catch (CryptoException e) {
            throw new TlsFatalAlert((short) 47);
        }
    }

    public void init(TlsContext tlsContext) {
        super.init(tlsContext);
        if (this.tlsSigner != null) {
            this.tlsSigner.init(tlsContext);
        }
    }

    protected Signer initVerifyer(TlsSigner tlsSigner, SecurityParameters securityParameters) {
        Signer createVerifyer = tlsSigner.createVerifyer(this.serverPublicKey);
        createVerifyer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        createVerifyer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return createVerifyer;
    }

    public void processClientCredentials(TlsCredentials tlsCredentials) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    public void processServerCertificate(Certificate certificate) throws IOException {
        if (this.tlsSigner == null) {
            throw new TlsFatalAlert((short) 10);
        } else if (certificate.isEmpty()) {
            throw new TlsFatalAlert((short) 42);
        } else {
            Certificate certificateAt = certificate.getCertificateAt(0);
            try {
                this.serverPublicKey = PublicKeyFactory.createKey(certificateAt.getSubjectPublicKeyInfo());
                if (this.tlsSigner.isValidPublicKey(this.serverPublicKey)) {
                    TlsUtils.validateKeyUsage(certificateAt, 128);
                    super.processServerCertificate(certificate);
                    return;
                }
                throw new TlsFatalAlert((short) 46);
            } catch (RuntimeException e) {
                throw new TlsFatalAlert((short) 43);
            }
        }
    }

    public void processServerKeyExchange(InputStream inputStream) throws IOException {
        InputStream signerInputStream;
        SecurityParameters securityParameters = this.context.getSecurityParameters();
        Signer signer = null;
        if (this.tlsSigner != null) {
            signer = initVerifyer(this.tlsSigner, securityParameters);
            signerInputStream = new SignerInputStream(inputStream, signer);
        } else {
            signerInputStream = inputStream;
        }
        byte[] readOpaque16 = TlsUtils.readOpaque16(signerInputStream);
        byte[] readOpaque162 = TlsUtils.readOpaque16(signerInputStream);
        byte[] readOpaque8 = TlsUtils.readOpaque8(signerInputStream);
        byte[] readOpaque163 = TlsUtils.readOpaque16(signerInputStream);
        if (signer == null || signer.verifySignature(TlsUtils.readOpaque16(inputStream))) {
            BigInteger bigInteger = new BigInteger(1, readOpaque16);
            BigInteger bigInteger2 = new BigInteger(1, readOpaque162);
            this.f502s = readOpaque8;
            try {
                this.f501B = SRP6Util.validatePublicValue(bigInteger, new BigInteger(1, readOpaque163));
                this.srpClient.init(bigInteger, bigInteger2, new SHA1Digest(), this.context.getSecureRandom());
                return;
            } catch (CryptoException e) {
                throw new TlsFatalAlert((short) 47);
            }
        }
        throw new TlsFatalAlert((short) 51);
    }

    public boolean requiresServerKeyExchange() {
        return true;
    }

    public void skipServerCredentials() throws IOException {
        if (this.tlsSigner != null) {
            throw new TlsFatalAlert((short) 10);
        }
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest) throws IOException {
        throw new TlsFatalAlert((short) 10);
    }
}
