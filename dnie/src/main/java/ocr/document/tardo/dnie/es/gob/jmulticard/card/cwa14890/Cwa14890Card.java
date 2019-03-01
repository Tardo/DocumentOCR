package es.gob.jmulticard.card.cwa14890;

import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;

public interface Cwa14890Card {
    boolean externalAuthentication(byte[] bArr) throws ApduConnectionException;

    byte[] getChallenge() throws ApduConnectionException;

    byte[] getChrCCvIfd();

    byte[] getIccCertEncoded() throws IOException;

    RSAPrivateKey getIfdPrivateKey();

    byte[] getInternalAuthenticateMessage(byte[] bArr, byte[] bArr2) throws ApduConnectionException;

    byte[] getRefIccPrivateKey();

    byte[] getSerialNumber() throws ApduConnectionException;

    void setKeysToAuthentication(byte[] bArr, byte[] bArr2) throws ApduConnectionException;

    void verifyCaIntermediateIcc() throws CertificateException, IOException;

    void verifyIcc() throws CertificateException, IOException;

    void verifyIfdCertificateChain() throws ApduConnectionException;
}
