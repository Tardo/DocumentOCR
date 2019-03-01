package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.io.Streams;

public class TlsRSAKeyExchange extends AbstractTlsKeyExchange {
    protected byte[] premasterSecret;
    protected RSAKeyParameters rsaServerPublicKey = null;
    protected TlsEncryptionCredentials serverCredentials = null;
    protected AsymmetricKeyParameter serverPublicKey = null;

    public TlsRSAKeyExchange(Vector vector) {
        super(1, vector);
    }

    public void generateClientKeyExchange(OutputStream outputStream) throws IOException {
        this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(this.context, this.rsaServerPublicKey, outputStream);
    }

    public byte[] generatePremasterSecret() throws IOException {
        if (this.premasterSecret == null) {
            throw new TlsFatalAlert((short) 80);
        }
        byte[] bArr = this.premasterSecret;
        this.premasterSecret = null;
        return bArr;
    }

    public void processClientCredentials(TlsCredentials tlsCredentials) throws IOException {
        if (!(tlsCredentials instanceof TlsSignerCredentials)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public void processClientKeyExchange(InputStream inputStream) throws IOException {
        byte[] readAll = this.context.getServerVersion().isSSL() ? Streams.readAll(inputStream) : TlsUtils.readOpaque16(inputStream);
        ProtocolVersion clientVersion = this.context.getClientVersion();
        byte[] bArr = new byte[48];
        this.context.getSecureRandom().nextBytes(bArr);
        byte[] bArr2 = TlsUtils.EMPTY_BYTES;
        try {
            readAll = this.serverCredentials.decryptPreMasterSecret(readAll);
        } catch (Exception e) {
            readAll = bArr2;
        }
        if (readAll.length != 48) {
            TlsUtils.writeVersion(clientVersion, bArr, 0);
            this.premasterSecret = bArr;
            return;
        }
        TlsUtils.writeVersion(clientVersion, readAll, 0);
        this.premasterSecret = readAll;
    }

    public void processServerCertificate(Certificate certificate) throws IOException {
        if (certificate.isEmpty()) {
            throw new TlsFatalAlert((short) 42);
        }
        Certificate certificateAt = certificate.getCertificateAt(0);
        try {
            this.serverPublicKey = PublicKeyFactory.createKey(certificateAt.getSubjectPublicKeyInfo());
            if (this.serverPublicKey.isPrivate()) {
                throw new TlsFatalAlert((short) 80);
            }
            this.rsaServerPublicKey = validateRSAPublicKey((RSAKeyParameters) this.serverPublicKey);
            TlsUtils.validateKeyUsage(certificateAt, 32);
            super.processServerCertificate(certificate);
        } catch (RuntimeException e) {
            throw new TlsFatalAlert((short) 43);
        }
    }

    public void processServerCredentials(TlsCredentials tlsCredentials) throws IOException {
        if (tlsCredentials instanceof TlsEncryptionCredentials) {
            processServerCertificate(tlsCredentials.getCertificate());
            this.serverCredentials = (TlsEncryptionCredentials) tlsCredentials;
            return;
        }
        throw new TlsFatalAlert((short) 80);
    }

    public void skipServerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 10);
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest) throws IOException {
        short[] certificateTypes = certificateRequest.getCertificateTypes();
        int i = 0;
        while (i < certificateTypes.length) {
            switch (certificateTypes[i]) {
                case (short) 1:
                case (short) 2:
                case (short) 64:
                    i++;
                default:
                    throw new TlsFatalAlert((short) 47);
            }
        }
    }

    protected RSAKeyParameters validateRSAPublicKey(RSAKeyParameters rSAKeyParameters) throws IOException {
        if (rSAKeyParameters.getExponent().isProbablePrime(2)) {
            return rSAKeyParameters;
        }
        throw new TlsFatalAlert((short) 47);
    }
}
