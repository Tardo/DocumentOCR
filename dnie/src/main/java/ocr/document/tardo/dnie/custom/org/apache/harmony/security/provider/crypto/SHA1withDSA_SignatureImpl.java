package custom.org.apache.harmony.security.provider.crypto;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import org.bouncycastle.crypto.tls.CipherSuite;

public class SHA1withDSA_SignatureImpl extends Signature {
    private DSAKey dsaKey;
    private MessageDigest msgDigest = MessageDigest.getInstance("SHA1");

    public SHA1withDSA_SignatureImpl() throws NoSuchAlgorithmException {
        super("SHA1withDSA");
    }

    protected Object engineGetParameter(String param) throws InvalidParameterException {
        if (param != null) {
            return null;
        }
        throw new NullPointerException(Messages.getString("security.01"));
    }

    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey == null || !(privateKey instanceof DSAPrivateKey)) {
            throw new InvalidKeyException(Messages.getString("security.168"));
        }
        DSAParams params = ((DSAPrivateKey) privateKey).getParams();
        BigInteger p = params.getP();
        BigInteger q = params.getQ();
        BigInteger x = ((DSAPrivateKey) privateKey).getX();
        int n = p.bitLength();
        if (p.compareTo(BigInteger.valueOf(1)) != 1 || n < 512 || n > 1024 || (n & 63) != 0) {
            throw new InvalidKeyException(Messages.getString("security.169"));
        } else if (q.signum() != 1 && q.bitLength() != CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256) {
            throw new InvalidKeyException(Messages.getString("security.16A"));
        } else if (x.signum() == 1 && x.compareTo(q) == -1) {
            this.dsaKey = (DSAKey) privateKey;
            this.msgDigest.reset();
        } else {
            throw new InvalidKeyException(Messages.getString("security.16B"));
        }
    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey == null || !(publicKey instanceof DSAPublicKey)) {
            throw new InvalidKeyException(Messages.getString("security.16C"));
        }
        DSAParams params = ((DSAPublicKey) publicKey).getParams();
        BigInteger p = params.getP();
        BigInteger q = params.getQ();
        BigInteger y = ((DSAPublicKey) publicKey).getY();
        int n1 = p.bitLength();
        if (p.compareTo(BigInteger.valueOf(1)) != 1 || n1 < 512 || n1 > 1024 || (n1 & 63) != 0) {
            throw new InvalidKeyException(Messages.getString("security.169"));
        } else if (q.signum() != 1 || q.bitLength() != CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256) {
            throw new InvalidKeyException(Messages.getString("security.16A"));
        } else if (y.signum() != 1) {
            throw new InvalidKeyException(Messages.getString("security.16D"));
        } else {
            this.dsaKey = (DSAKey) publicKey;
            this.msgDigest.reset();
        }
    }

    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        if (param == null) {
            throw new NullPointerException(Messages.getString("security.83", (Object) "param"));
        }
        throw new InvalidParameterException(Messages.getString("security.16E"));
    }

    protected byte[] engineSign() throws SignatureException {
        BigInteger r;
        BigInteger s;
        int n;
        if (this.appRandom == null) {
            this.appRandom = new SecureRandom();
        }
        DSAParams params = this.dsaKey.getParams();
        BigInteger p = params.getP();
        BigInteger q = params.getQ();
        BigInteger g = params.getG();
        BigInteger x = ((DSAPrivateKey) this.dsaKey).getX();
        BigInteger digestBI = new BigInteger(1, this.msgDigest.digest());
        byte[] randomBytes = new byte[20];
        while (true) {
            this.appRandom.nextBytes(randomBytes);
            BigInteger k = new BigInteger(1, randomBytes);
            if (k.compareTo(q) == -1) {
                r = g.modPow(k, p).mod(q);
                if (r.signum() != 0) {
                    s = k.modInverse(q).multiply(digestBI.add(x.multiply(r)).mod(q)).mod(q);
                    if (s.signum() != 0) {
                        break;
                    }
                } else {
                    continue;
                }
            }
        }
        byte[] rBytes = r.toByteArray();
        int n1 = rBytes.length;
        if ((rBytes[0] & 128) != 0) {
            n1++;
        }
        Object sBytes = s.toByteArray();
        int n2 = sBytes.length;
        if ((sBytes[0] & 128) != 0) {
            n2++;
        }
        Object signature = new byte[((n1 + 6) + n2)];
        signature[0] = (byte) 48;
        signature[1] = (byte) ((n1 + 4) + n2);
        signature[2] = (byte) 2;
        signature[3] = (byte) n1;
        signature[n1 + 4] = (byte) 2;
        signature[n1 + 5] = (byte) n2;
        if (n1 == rBytes.length) {
            n = 4;
        } else {
            n = 5;
        }
        System.arraycopy(rBytes, 0, signature, n, rBytes.length);
        if (n2 == sBytes.length) {
            n = n1 + 6;
        } else {
            n = n1 + 7;
        }
        System.arraycopy(sBytes, 0, signature, n, sBytes.length);
        return signature;
    }

    protected void engineUpdate(byte b) throws SignatureException {
        this.msgDigest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.msgDigest.update(b, off, len);
    }

    private boolean checkSignature(byte[] sigBytes, int offset, int length) throws SignatureException {
        try {
            int n1 = sigBytes[offset + 3];
            int n2 = sigBytes[(offset + n1) + 5];
            if (sigBytes[offset + 0] == (byte) 48 && sigBytes[offset + 2] == (byte) 2 && sigBytes[(offset + n1) + 4] == (byte) 2 && sigBytes[offset + 1] == (n1 + n2) + 4 && n1 <= 21 && n2 <= 21 && (length == 0 || sigBytes[offset + 1] + 2 <= length)) {
                byte b = sigBytes[(n1 + 5) + n2];
                byte[] digest = this.msgDigest.digest();
                byte[] bytes = new byte[n1];
                System.arraycopy(sigBytes, offset + 4, bytes, 0, n1);
                BigInteger r = new BigInteger(bytes);
                bytes = new byte[n2];
                System.arraycopy(sigBytes, (offset + 6) + n1, bytes, 0, n2);
                BigInteger s = new BigInteger(bytes);
                DSAParams params = this.dsaKey.getParams();
                BigInteger p = params.getP();
                BigInteger q = params.getQ();
                BigInteger g = params.getG();
                BigInteger y = ((DSAPublicKey) this.dsaKey).getY();
                if (r.signum() != 1 || r.compareTo(q) != -1 || s.signum() != 1 || s.compareTo(q) != -1) {
                    return false;
                }
                BigInteger w = s.modInverse(q);
                if (g.modPow(new BigInteger(1, digest).multiply(w).mod(q), p).multiply(y.modPow(r.multiply(w).mod(q), p)).mod(p).mod(q).compareTo(r) != 0) {
                    return false;
                }
                return true;
            }
            throw new SignatureException(Messages.getString("security.16F"));
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new SignatureException(Messages.getString("security.170"));
        }
    }

    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (sigBytes != null) {
            return checkSignature(sigBytes, 0, 0);
        }
        throw new NullPointerException(Messages.getString("security.83", (Object) "sigBytes"));
    }

    protected boolean engineVerify(byte[] sigBytes, int offset, int length) throws SignatureException {
        return checkSignature(sigBytes, offset, length);
    }
}
