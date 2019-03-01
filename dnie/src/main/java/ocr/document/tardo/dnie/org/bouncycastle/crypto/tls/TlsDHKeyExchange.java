package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Vector;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class TlsDHKeyExchange extends AbstractTlsKeyExchange {
    protected static final BigInteger ONE = BigInteger.valueOf(1);
    protected static final BigInteger TWO = BigInteger.valueOf(2);
    protected TlsAgreementCredentials agreementCredentials;
    protected DHPrivateKeyParameters dhAgreeClientPrivateKey;
    protected DHPublicKeyParameters dhAgreeClientPublicKey;
    protected DHPublicKeyParameters dhAgreeServerPublicKey;
    protected DHParameters dhParameters;
    protected AsymmetricKeyParameter serverPublicKey;
    protected TlsSigner tlsSigner;

    public TlsDHKeyExchange(int i, Vector vector, DHParameters dHParameters) {
        super(i, vector);
        switch (i) {
            case 3:
                this.tlsSigner = new TlsDSSSigner();
                break;
            case 5:
                this.tlsSigner = new TlsRSASigner();
                break;
            case 7:
            case 9:
                this.tlsSigner = null;
                break;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
        this.dhParameters = dHParameters;
    }

    protected boolean areCompatibleParameters(DHParameters dHParameters, DHParameters dHParameters2) {
        return dHParameters.getP().equals(dHParameters2.getP()) && dHParameters.getG().equals(dHParameters2.getG());
    }

    protected byte[] calculateDHBasicAgreement(DHPublicKeyParameters dHPublicKeyParameters, DHPrivateKeyParameters dHPrivateKeyParameters) {
        return TlsDHUtils.calculateDHBasicAgreement(dHPublicKeyParameters, dHPrivateKeyParameters);
    }

    public void generateClientKeyExchange(OutputStream outputStream) throws IOException {
        if (this.agreementCredentials == null) {
            this.dhAgreeClientPrivateKey = TlsDHUtils.generateEphemeralClientKeyExchange(this.context.getSecureRandom(), this.dhAgreeServerPublicKey.getParameters(), outputStream);
        }
    }

    protected AsymmetricCipherKeyPair generateDHKeyPair(DHParameters dHParameters) {
        return TlsDHUtils.generateDHKeyPair(this.context.getSecureRandom(), dHParameters);
    }

    public byte[] generatePremasterSecret() throws IOException {
        return this.agreementCredentials != null ? this.agreementCredentials.generateAgreement(this.dhAgreeServerPublicKey) : calculateDHBasicAgreement(this.dhAgreeServerPublicKey, this.dhAgreeClientPrivateKey);
    }

    public void init(TlsContext tlsContext) {
        super.init(tlsContext);
        if (this.tlsSigner != null) {
            this.tlsSigner.init(tlsContext);
        }
    }

    public void processClientCredentials(TlsCredentials tlsCredentials) throws IOException {
        if (tlsCredentials instanceof TlsAgreementCredentials) {
            this.agreementCredentials = (TlsAgreementCredentials) tlsCredentials;
        } else if (!(tlsCredentials instanceof TlsSignerCredentials)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public void processServerCertificate(Certificate certificate) throws IOException {
        if (certificate.isEmpty()) {
            throw new TlsFatalAlert((short) 42);
        }
        Certificate certificateAt = certificate.getCertificateAt(0);
        try {
            this.serverPublicKey = PublicKeyFactory.createKey(certificateAt.getSubjectPublicKeyInfo());
            if (this.tlsSigner == null) {
                try {
                    this.dhAgreeServerPublicKey = validateDHPublicKey((DHPublicKeyParameters) this.serverPublicKey);
                    TlsUtils.validateKeyUsage(certificateAt, 8);
                } catch (ClassCastException e) {
                    throw new TlsFatalAlert((short) 46);
                }
            } else if (this.tlsSigner.isValidPublicKey(this.serverPublicKey)) {
                TlsUtils.validateKeyUsage(certificateAt, 128);
            } else {
                throw new TlsFatalAlert((short) 46);
            }
            super.processServerCertificate(certificate);
        } catch (RuntimeException e2) {
            throw new TlsFatalAlert((short) 43);
        }
    }

    public boolean requiresServerKeyExchange() {
        switch (this.keyExchange) {
            case 3:
            case 5:
            case 11:
                return true;
            default:
                return false;
        }
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
                case (short) 3:
                case (short) 4:
                case (short) 64:
                    i++;
                default:
                    throw new TlsFatalAlert((short) 47);
            }
        }
    }

    protected DHPublicKeyParameters validateDHPublicKey(DHPublicKeyParameters dHPublicKeyParameters) throws IOException {
        return TlsDHUtils.validateDHPublicKey(dHPublicKeyParameters);
    }
}
