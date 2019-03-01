package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Vector;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.io.SignerInputStream;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

public class TlsDHEKeyExchange extends TlsDHKeyExchange {
    protected TlsSignerCredentials serverCredentials = null;

    public TlsDHEKeyExchange(int i, Vector vector, DHParameters dHParameters) {
        super(i, vector, dHParameters);
    }

    public byte[] generateServerKeyExchange() throws IOException {
        if (this.dhParameters == null) {
            throw new TlsFatalAlert((short) 80);
        }
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DHKeyPairGenerator dHKeyPairGenerator = new DHKeyPairGenerator();
        dHKeyPairGenerator.init(new DHKeyGenerationParameters(this.context.getSecureRandom(), this.dhParameters));
        BigInteger y = ((DHPublicKeyParameters) dHKeyPairGenerator.generateKeyPair().getPublic()).getY();
        TlsDHUtils.writeDHParameter(this.dhParameters.getP(), byteArrayOutputStream);
        TlsDHUtils.writeDHParameter(this.dhParameters.getG(), byteArrayOutputStream);
        TlsDHUtils.writeDHParameter(y, byteArrayOutputStream);
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        Digest combinedHash = new CombinedHash();
        SecurityParameters securityParameters = this.context.getSecurityParameters();
        combinedHash.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        combinedHash.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        combinedHash.update(toByteArray, 0, toByteArray.length);
        toByteArray = new byte[combinedHash.getDigestSize()];
        combinedHash.doFinal(toByteArray, 0);
        TlsUtils.writeOpaque16(this.serverCredentials.generateCertificateSignature(toByteArray), byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected Signer initVerifyer(TlsSigner tlsSigner, SecurityParameters securityParameters) {
        Signer createVerifyer = tlsSigner.createVerifyer(this.serverPublicKey);
        createVerifyer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        createVerifyer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return createVerifyer;
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
        BigInteger readDHParameter = TlsDHUtils.readDHParameter(signerInputStream);
        BigInteger readDHParameter2 = TlsDHUtils.readDHParameter(signerInputStream);
        BigInteger readDHParameter3 = TlsDHUtils.readDHParameter(signerInputStream);
        if (initVerifyer.verifySignature(TlsUtils.readOpaque16(inputStream))) {
            this.dhAgreeServerPublicKey = validateDHPublicKey(new DHPublicKeyParameters(readDHParameter3, new DHParameters(readDHParameter, readDHParameter2)));
            return;
        }
        throw new TlsFatalAlert((short) 51);
    }
}
