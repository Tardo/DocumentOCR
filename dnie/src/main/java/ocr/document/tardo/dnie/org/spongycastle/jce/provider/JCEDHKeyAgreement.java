package org.spongycastle.jce.provider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.spongycastle.crypto.params.DESParameters;
import org.spongycastle.util.Strings;

public class JCEDHKeyAgreement extends KeyAgreementSpi {
    private static final Hashtable algorithms = new Hashtable();
    /* renamed from: g */
    private BigInteger f174g;
    /* renamed from: p */
    private BigInteger f175p;
    private BigInteger result;
    /* renamed from: x */
    private BigInteger f176x;

    static {
        Integer i64 = new Integer(64);
        Integer i192 = new Integer(192);
        Integer i128 = new Integer(128);
        Integer i256 = new Integer(256);
        algorithms.put("DES", i64);
        algorithms.put("DESEDE", i192);
        algorithms.put("BLOWFISH", i128);
        algorithms.put("AES", i256);
    }

    private byte[] bigIntToBytes(BigInteger r) {
        byte[] tmp = r.toByteArray();
        if (tmp[0] != (byte) 0) {
            return tmp;
        }
        byte[] ntmp = new byte[(tmp.length - 1)];
        System.arraycopy(tmp, 1, ntmp, 0, ntmp.length);
        return ntmp;
    }

    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (this.f176x == null) {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        } else if (key instanceof DHPublicKey) {
            DHPublicKey pubKey = (DHPublicKey) key;
            if (!pubKey.getParams().getG().equals(this.f174g) || !pubKey.getParams().getP().equals(this.f175p)) {
                throw new InvalidKeyException("DHPublicKey not for this KeyAgreement!");
            } else if (lastPhase) {
                this.result = ((DHPublicKey) key).getY().modPow(this.f176x, this.f175p);
                return null;
            } else {
                this.result = ((DHPublicKey) key).getY().modPow(this.f176x, this.f175p);
                return new JCEDHPublicKey(this.result, pubKey.getParams());
            }
        } else {
            throw new InvalidKeyException("DHKeyAgreement doPhase requires DHPublicKey");
        }
    }

    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (this.f176x != null) {
            return bigIntToBytes(this.result);
        }
        throw new IllegalStateException("Diffie-Hellman not initialised.");
    }

    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws IllegalStateException, ShortBufferException {
        if (this.f176x == null) {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        }
        byte[] secret = bigIntToBytes(this.result);
        if (sharedSecret.length - offset < secret.length) {
            throw new ShortBufferException("DHKeyAgreement - buffer too short");
        }
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }

    protected SecretKey engineGenerateSecret(String algorithm) {
        if (this.f176x == null) {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        }
        String algKey = Strings.toUpperCase(algorithm);
        byte[] res = bigIntToBytes(this.result);
        if (!algorithms.containsKey(algKey)) {
            return new SecretKeySpec(res, algorithm);
        }
        byte[] key = new byte[(((Integer) algorithms.get(algKey)).intValue() / 8)];
        System.arraycopy(res, 0, key, 0, key.length);
        if (algKey.startsWith("DES")) {
            DESParameters.setOddParity(key);
        }
        return new SecretKeySpec(key, algorithm);
    }

    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key instanceof DHPrivateKey) {
            DHPrivateKey privKey = (DHPrivateKey) key;
            if (params == null) {
                this.f175p = privKey.getParams().getP();
                this.f174g = privKey.getParams().getG();
            } else if (params instanceof DHParameterSpec) {
                DHParameterSpec p = (DHParameterSpec) params;
                this.f175p = p.getP();
                this.f174g = p.getG();
            } else {
                throw new InvalidAlgorithmParameterException("DHKeyAgreement only accepts DHParameterSpec");
            }
            BigInteger x = privKey.getX();
            this.result = x;
            this.f176x = x;
            return;
        }
        throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey for initialisation");
    }

    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        if (key instanceof DHPrivateKey) {
            DHPrivateKey privKey = (DHPrivateKey) key;
            this.f175p = privKey.getParams().getP();
            this.f174g = privKey.getParams().getG();
            BigInteger x = privKey.getX();
            this.result = x;
            this.f176x = x;
            return;
        }
        throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey");
    }
}
