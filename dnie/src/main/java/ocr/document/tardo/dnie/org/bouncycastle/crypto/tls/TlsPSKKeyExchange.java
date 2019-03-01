package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Vector;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class TlsPSKKeyExchange extends AbstractTlsKeyExchange {
    protected DHPrivateKeyParameters dhAgreeClientPrivateKey = null;
    protected DHPublicKeyParameters dhAgreeServerPublicKey = null;
    protected byte[] premasterSecret;
    protected TlsPSKIdentity pskIdentity;
    protected byte[] psk_identity_hint = null;
    protected RSAKeyParameters rsaServerPublicKey = null;
    protected AsymmetricKeyParameter serverPublicKey = null;

    public TlsPSKKeyExchange(int i, Vector vector, TlsPSKIdentity tlsPSKIdentity) {
        super(i, vector);
        switch (i) {
            case 13:
            case 14:
            case 15:
                this.pskIdentity = tlsPSKIdentity;
                return;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    public void generateClientKeyExchange(OutputStream outputStream) throws IOException {
        if (this.psk_identity_hint == null) {
            this.pskIdentity.skipIdentityHint();
        } else {
            this.pskIdentity.notifyIdentityHint(this.psk_identity_hint);
        }
        TlsUtils.writeOpaque16(this.pskIdentity.getPSKIdentity(), outputStream);
        if (this.keyExchange == 15) {
            this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(this.context, this.rsaServerPublicKey, outputStream);
        } else if (this.keyExchange == 14) {
            this.dhAgreeClientPrivateKey = TlsDHUtils.generateEphemeralClientKeyExchange(this.context.getSecureRandom(), this.dhAgreeServerPublicKey.getParameters(), outputStream);
        }
    }

    protected byte[] generateOtherSecret(int i) {
        return this.keyExchange == 14 ? TlsDHUtils.calculateDHBasicAgreement(this.dhAgreeServerPublicKey, this.dhAgreeClientPrivateKey) : this.keyExchange == 15 ? this.premasterSecret : new byte[i];
    }

    public byte[] generatePremasterSecret() throws IOException {
        byte[] psk = this.pskIdentity.getPSK();
        byte[] generateOtherSecret = generateOtherSecret(psk.length);
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream((generateOtherSecret.length + 4) + psk.length);
        TlsUtils.writeOpaque16(generateOtherSecret, byteArrayOutputStream);
        TlsUtils.writeOpaque16(psk, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    public void processClientCredentials(TlsCredentials tlsCredentials) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    public void processServerCertificate(Certificate certificate) throws IOException {
        if (this.keyExchange != 15) {
            throw new TlsFatalAlert((short) 10);
        } else if (certificate.isEmpty()) {
            throw new TlsFatalAlert((short) 42);
        } else {
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
    }

    public void processServerKeyExchange(InputStream inputStream) throws IOException {
        this.psk_identity_hint = TlsUtils.readOpaque16(inputStream);
        if (this.keyExchange == 14) {
            byte[] readOpaque16 = TlsUtils.readOpaque16(inputStream);
            byte[] readOpaque162 = TlsUtils.readOpaque16(inputStream);
            this.dhAgreeServerPublicKey = TlsDHUtils.validateDHPublicKey(new DHPublicKeyParameters(new BigInteger(1, TlsUtils.readOpaque16(inputStream)), new DHParameters(new BigInteger(1, readOpaque16), new BigInteger(1, readOpaque162))));
        }
    }

    public boolean requiresServerKeyExchange() {
        return this.keyExchange == 14;
    }

    public void skipServerCredentials() throws IOException {
        if (this.keyExchange == 15) {
            throw new TlsFatalAlert((short) 10);
        }
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest) throws IOException {
        throw new TlsFatalAlert((short) 10);
    }

    protected RSAKeyParameters validateRSAPublicKey(RSAKeyParameters rSAKeyParameters) throws IOException {
        if (rSAKeyParameters.getExponent().isProbablePrime(2)) {
            return rSAKeyParameters;
        }
        throw new TlsFatalAlert((short) 47);
    }
}
