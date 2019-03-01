package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.io.SignerInputStream;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public class TlsECDHEKeyExchange extends TlsECDHKeyExchange {
    protected TlsSignerCredentials serverCredentials = null;

    public TlsECDHEKeyExchange(int i, Vector vector, int[] iArr, short[] sArr, short[] sArr2) {
        super(i, vector, iArr, sArr, sArr2);
    }

    public byte[] generateServerKeyExchange() throws IOException {
        int i;
        if (this.namedCurves == null) {
            i = 23;
        } else {
            for (int i2 : this.namedCurves) {
                if (TlsECCUtils.isSupportedNamedCurve(i2)) {
                    break;
                }
            }
            i2 = -1;
        }
        ECDomainParameters parametersForNamedCurve = i2 >= 0 ? TlsECCUtils.getParametersForNamedCurve(i2) : TlsProtocol.arrayContains(this.namedCurves, 65281) ? TlsECCUtils.getParametersForNamedCurve(23) : TlsProtocol.arrayContains(this.namedCurves, 65282) ? TlsECCUtils.getParametersForNamedCurve(7) : null;
        if (parametersForNamedCurve == null) {
            throw new TlsFatalAlert((short) 80);
        }
        AsymmetricCipherKeyPair generateECKeyPair = TlsECCUtils.generateECKeyPair(this.context.getSecureRandom(), parametersForNamedCurve);
        this.ecAgreeServerPrivateKey = (ECPrivateKeyParameters) generateECKeyPair.getPrivate();
        byte[] serializeECPublicKey = TlsECCUtils.serializeECPublicKey(this.clientECPointFormats, (ECPublicKeyParameters) generateECKeyPair.getPublic());
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        if (i2 < 0) {
            TlsECCUtils.writeExplicitECParameters(this.clientECPointFormats, parametersForNamedCurve, byteArrayOutputStream);
        } else {
            TlsECCUtils.writeNamedECParameters(i2, byteArrayOutputStream);
        }
        TlsUtils.writeOpaque8(serializeECPublicKey, byteArrayOutputStream);
        serializeECPublicKey = byteArrayOutputStream.toByteArray();
        Digest combinedHash = new CombinedHash();
        SecurityParameters securityParameters = this.context.getSecurityParameters();
        combinedHash.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        combinedHash.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        combinedHash.update(serializeECPublicKey, 0, serializeECPublicKey.length);
        serializeECPublicKey = new byte[combinedHash.getDigestSize()];
        combinedHash.doFinal(serializeECPublicKey, 0);
        TlsUtils.writeOpaque16(this.serverCredentials.generateCertificateSignature(serializeECPublicKey), byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected Signer initVerifyer(TlsSigner tlsSigner, SecurityParameters securityParameters) {
        Signer createVerifyer = tlsSigner.createVerifyer(this.serverPublicKey);
        createVerifyer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        createVerifyer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return createVerifyer;
    }

    public void processClientCredentials(TlsCredentials tlsCredentials) throws IOException {
        if (!(tlsCredentials instanceof TlsSignerCredentials)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public void processServerCredentials(TlsCredentials tlsCredentials) throws IOException {
        if (tlsCredentials instanceof TlsSignerCredentials) {
            processServerCertificate(tlsCredentials.getCertificate());
            this.serverCredentials = (TlsSignerCredentials) tlsCredentials;
            return;
        }
        throw new TlsFatalAlert((short) 80);
    }

    public void processServerKeyExchange(InputStream inputStream) throws IOException {
        Signer initVerifyer = initVerifyer(this.tlsSigner, this.context.getSecurityParameters());
        InputStream signerInputStream = new SignerInputStream(inputStream, initVerifyer);
        ECDomainParameters readECParameters = TlsECCUtils.readECParameters(this.namedCurves, this.clientECPointFormats, signerInputStream);
        byte[] readOpaque8 = TlsUtils.readOpaque8(signerInputStream);
        if (initVerifyer.verifySignature(TlsUtils.readOpaque16(inputStream))) {
            this.ecAgreeServerPublicKey = TlsECCUtils.validateECPublicKey(TlsECCUtils.deserializeECPublicKey(this.clientECPointFormats, readECParameters, readOpaque8));
            return;
        }
        throw new TlsFatalAlert((short) 51);
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
}
