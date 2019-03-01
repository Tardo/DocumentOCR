package es.gob.jmulticard;

import java.io.IOException;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public interface CryptoHelper {
    byte[] desDecrypt(byte[] bArr, byte[] bArr2) throws IOException;

    byte[] desEncrypt(byte[] bArr, byte[] bArr2) throws IOException;

    byte[] desedeDecrypt(byte[] bArr, byte[] bArr2) throws IOException;

    byte[] desedeEncrypt(byte[] bArr, byte[] bArr2) throws IOException;

    byte[] digest(String str, byte[] bArr) throws IOException;

    Certificate generateCertificate(byte[] bArr) throws CertificateException;

    byte[] generateRandomBytes(int i) throws IOException;

    byte[] rsaDecrypt(byte[] bArr, Key key) throws IOException;

    byte[] rsaEncrypt(byte[] bArr, Key key) throws IOException;
}
