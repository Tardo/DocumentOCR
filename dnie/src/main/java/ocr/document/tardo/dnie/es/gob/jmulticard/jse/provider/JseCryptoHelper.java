package es.gob.jmulticard.jse.provider;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.jse.provider.digest.Digest;
import es.gob.jmulticard.jse.provider.digest.SHA1Digest;
import es.gob.jmulticard.jse.provider.digest.SHA256Digest;
import es.gob.jmulticard.jse.provider.digest.SHA384Digest;
import es.gob.jmulticard.jse.provider.digest.SHA512Digest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2ParameterSpec;

public final class JseCryptoHelper implements CryptoHelper {
    private static final String NONE = "NONE";
    private static final String SHA1 = "SHA-1";
    private static final String SHA256 = "SHA-256";
    private static final String SHA384 = "SHA-384";
    private static final String SHA512 = "SHA-512";

    public byte[] digest(String algorithm, byte[] data) throws IOException {
        if (algorithm == null) {
            throw new IllegalArgumentException("El algoritmo de huella digital no puede ser nulo");
        } else if (NONE.equals(algorithm)) {
            return data;
        } else {
            try {
                Digest digest = selectMessageDigest(normalizeDigestAlgorithm(algorithm));
                digest.update(data, 0, data.length);
                byte[] result = new byte[digest.getDigestSize()];
                digest.doFinal(result, 0);
                return result;
            } catch (Exception e) {
                throw new IOException("Error obteniendo la huella digital de los datos: " + e, e);
            }
        }
    }

    private static Digest selectMessageDigest(String digestAlgorithm) {
        if (SHA1.equals(digestAlgorithm)) {
            return new SHA1Digest();
        }
        if (SHA256.equals(digestAlgorithm)) {
            return new SHA256Digest();
        }
        if (SHA384.equals(digestAlgorithm)) {
            return new SHA384Digest();
        }
        if (SHA512.equals(digestAlgorithm)) {
            return new SHA512Digest();
        }
        return null;
    }

    private static String normalizeDigestAlgorithm(String algorithm) {
        if ("SHA".equalsIgnoreCase(algorithm) || "SHA1".equalsIgnoreCase(algorithm) || SHA1.equalsIgnoreCase(algorithm)) {
            return SHA1;
        }
        if (McElieceCCA2ParameterSpec.DEFAULT_MD.equalsIgnoreCase(algorithm) || SHA256.equalsIgnoreCase(algorithm)) {
            return SHA256;
        }
        if ("SHA384".equalsIgnoreCase(algorithm) || SHA384.equalsIgnoreCase(algorithm)) {
            return SHA384;
        }
        if ("SHA512".equalsIgnoreCase(algorithm) || SHA512.equalsIgnoreCase(algorithm)) {
            return SHA512;
        }
        return null;
    }

    private static byte[] doDesede(byte[] data, byte[] key, int direction) throws IOException {
        int i;
        byte[] ivBytes = new byte[8];
        for (i = 0; i < 8; i++) {
            ivBytes[i] = (byte) 0;
        }
        SecretKey k = new SecretKeySpec(prepareDesedeKey(key), "DESede");
        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(direction, k, new IvParameterSpec(ivBytes));
            byte[] cipheredData = cipher.doFinal(data);
            for (i = 0; i < data.length; i++) {
                data[i] = (byte) 0;
            }
            return cipheredData;
        } catch (Exception e) {
            for (i = 0; i < data.length; i++) {
                data[i] = (byte) 0;
            }
            throw new IOException("Error encriptando datos: " + e, e);
        }
    }

    public byte[] desedeEncrypt(byte[] data, byte[] key) throws IOException {
        return doDesede(data, key, 1);
    }

    public byte[] desedeDecrypt(byte[] data, byte[] key) throws IOException {
        return doDesede(data, key, 2);
    }

    private static byte[] prepareDesedeKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("La clave 3DES no puede ser nula");
        } else if (key.length == 24) {
            return key;
        } else {
            if (key.length == 16) {
                byte[] newKey = new byte[24];
                System.arraycopy(key, 0, newKey, 0, 16);
                System.arraycopy(key, 0, newKey, 16, 8);
                return newKey;
            }
            throw new IllegalArgumentException("Longitud de clave invalida, se esperaba 16 o 24, pero se indico " + Integer.toString(key.length));
        }
    }

    private static byte[] doDes(byte[] data, byte[] key, int direction) throws IOException {
        if (key == null) {
            throw new IllegalArgumentException("La clave DES no puede ser nula");
        } else if (key.length != 8) {
            throw new IllegalArgumentException("La clave DES debe ser de 8 octetos, pero la proporcionada es de " + key.length);
        } else {
            try {
                Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
                cipher.init(direction, new SecretKeySpec(key, "DES"));
                return cipher.doFinal(data);
            } catch (Exception e) {
                throw new IOException("Error cifrando los datos con DES: " + e);
            }
        }
    }

    public byte[] desEncrypt(byte[] data, byte[] key) throws IOException {
        return doDes(data, key, 1);
    }

    public byte[] desDecrypt(byte[] data, byte[] key) throws IOException {
        return doDes(data, key, 2);
    }

    private static byte[] doRsa(byte[] cipheredData, Key key, int direction) throws IOException {
        try {
            Cipher dec = Cipher.getInstance("RSA/ECB/NOPADDING");
            dec.init(direction, key);
            return dec.doFinal(cipheredData);
        } catch (Exception e) {
            throw new IOException("Error descifrando los datos mediante la clave RSA: " + e, e);
        }
    }

    public byte[] rsaDecrypt(byte[] cipheredData, Key key) throws IOException {
        return doRsa(cipheredData, key, 2);
    }

    public byte[] rsaEncrypt(byte[] data, Key key) throws IOException {
        return doRsa(data, key, 1);
    }

    public Certificate generateCertificate(byte[] encode) throws CertificateException {
        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encode));
    }

    public byte[] generateRandomBytes(int numBytes) throws IOException {
        try {
            byte[] randomBytes = new byte[numBytes];
            SecureRandom.getInstance("SHA1PRNG").nextBytes(randomBytes);
            return randomBytes;
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Algoritmo de generacion de aleatorios no valido: " + e, e);
        }
    }
}
