package org.spongycastle.jce.provider;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.spongycastle.asn1.oiw.OIWObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x9.X9ObjectIdentifiers;
import org.spongycastle.jce.interfaces.ElGamalPrivateKey;
import org.spongycastle.jce.interfaces.ElGamalPublicKey;
import org.spongycastle.jce.spec.ElGamalPrivateKeySpec;
import org.spongycastle.jce.spec.ElGamalPublicKeySpec;
import org.spongycastle.jce.spec.GOST3410PrivateKeySpec;
import org.spongycastle.jce.spec.GOST3410PublicKeySpec;

public abstract class JDKKeyFactory extends KeyFactorySpi {
    protected boolean elGamalFactory = false;

    public static class DH extends JDKKeyFactory {
        protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof DHPrivateKeySpec) {
                return new JCEDHPrivateKey((DHPrivateKeySpec) keySpec);
            }
            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof DHPublicKeySpec) {
                return new JCEDHPublicKey((DHPublicKeySpec) keySpec);
            }
            return super.engineGeneratePublic(keySpec);
        }
    }

    public static class DSA extends JDKKeyFactory {
        protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof DSAPrivateKeySpec) {
                return new JDKDSAPrivateKey((DSAPrivateKeySpec) keySpec);
            }
            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof DSAPublicKeySpec) {
                return new JDKDSAPublicKey((DSAPublicKeySpec) keySpec);
            }
            return super.engineGeneratePublic(keySpec);
        }
    }

    public static class ElGamal extends JDKKeyFactory {
        public ElGamal() {
            this.elGamalFactory = true;
        }

        protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof ElGamalPrivateKeySpec) {
                return new JCEElGamalPrivateKey((ElGamalPrivateKeySpec) keySpec);
            }
            if (keySpec instanceof DHPrivateKeySpec) {
                return new JCEElGamalPrivateKey((DHPrivateKeySpec) keySpec);
            }
            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof ElGamalPublicKeySpec) {
                return new JCEElGamalPublicKey((ElGamalPublicKeySpec) keySpec);
            }
            if (keySpec instanceof DHPublicKeySpec) {
                return new JCEElGamalPublicKey((DHPublicKeySpec) keySpec);
            }
            return super.engineGeneratePublic(keySpec);
        }
    }

    public static class GOST3410 extends JDKKeyFactory {
        protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof GOST3410PrivateKeySpec) {
                return new JDKGOST3410PrivateKey((GOST3410PrivateKeySpec) keySpec);
            }
            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof GOST3410PublicKeySpec) {
                return new JDKGOST3410PublicKey((GOST3410PublicKeySpec) keySpec);
            }
            return super.engineGeneratePublic(keySpec);
        }
    }

    public static class RSA extends JDKKeyFactory {
        protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof PKCS8EncodedKeySpec) {
                try {
                    return JDKKeyFactory.createPrivateKeyFromDERStream(((PKCS8EncodedKeySpec) keySpec).getEncoded());
                } catch (Exception e) {
                    try {
                        return new JCERSAPrivateCrtKey(new RSAPrivateKeyStructure((ASN1Sequence) ASN1Object.fromByteArray(((PKCS8EncodedKeySpec) keySpec).getEncoded())));
                    } catch (Exception ex) {
                        throw new InvalidKeySpecException(ex.toString());
                    }
                }
            } else if (keySpec instanceof RSAPrivateCrtKeySpec) {
                return new JCERSAPrivateCrtKey((RSAPrivateCrtKeySpec) keySpec);
            } else {
                if (keySpec instanceof RSAPrivateKeySpec) {
                    return new JCERSAPrivateKey((RSAPrivateKeySpec) keySpec);
                }
                throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.getClass().getName());
            }
        }

        protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof RSAPublicKeySpec) {
                return new JCERSAPublicKey((RSAPublicKeySpec) keySpec);
            }
            return super.engineGeneratePublic(keySpec);
        }
    }

    public static class X509 extends JDKKeyFactory {
    }

    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            try {
                return createPrivateKeyFromDERStream(((PKCS8EncodedKeySpec) keySpec).getEncoded());
            } catch (Exception e) {
                throw new InvalidKeySpecException(e.toString());
            }
        }
        throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.getClass().getName());
    }

    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            try {
                return createPublicKeyFromDERStream(((X509EncodedKeySpec) keySpec).getEncoded());
            } catch (Exception e) {
                throw new InvalidKeySpecException(e.toString());
            }
        }
        throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.getClass().getName());
    }

    protected KeySpec engineGetKeySpec(Key key, Class spec) throws InvalidKeySpecException {
        if (spec.isAssignableFrom(PKCS8EncodedKeySpec.class) && key.getFormat().equals("PKCS#8")) {
            return new PKCS8EncodedKeySpec(key.getEncoded());
        }
        if (spec.isAssignableFrom(X509EncodedKeySpec.class) && key.getFormat().equals("X.509")) {
            return new X509EncodedKeySpec(key.getEncoded());
        }
        if (spec.isAssignableFrom(RSAPublicKeySpec.class) && (key instanceof RSAPublicKey)) {
            RSAPublicKey k = (RSAPublicKey) key;
            return new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent());
        } else if (spec.isAssignableFrom(RSAPrivateKeySpec.class) && (key instanceof RSAPrivateKey)) {
            RSAPrivateKey k2 = (RSAPrivateKey) key;
            return new RSAPrivateKeySpec(k2.getModulus(), k2.getPrivateExponent());
        } else if (spec.isAssignableFrom(RSAPrivateCrtKeySpec.class) && (key instanceof RSAPrivateCrtKey)) {
            RSAPrivateCrtKey k3 = (RSAPrivateCrtKey) key;
            return new RSAPrivateCrtKeySpec(k3.getModulus(), k3.getPublicExponent(), k3.getPrivateExponent(), k3.getPrimeP(), k3.getPrimeQ(), k3.getPrimeExponentP(), k3.getPrimeExponentQ(), k3.getCrtCoefficient());
        } else if (spec.isAssignableFrom(DHPrivateKeySpec.class) && (key instanceof DHPrivateKey)) {
            DHPrivateKey k4 = (DHPrivateKey) key;
            return new DHPrivateKeySpec(k4.getX(), k4.getParams().getP(), k4.getParams().getG());
        } else if (spec.isAssignableFrom(DHPublicKeySpec.class) && (key instanceof DHPublicKey)) {
            DHPublicKey k5 = (DHPublicKey) key;
            return new DHPublicKeySpec(k5.getY(), k5.getParams().getP(), k5.getParams().getG());
        } else {
            throw new RuntimeException("not implemented yet " + key + " " + spec);
        }
    }

    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof RSAPublicKey) {
            return new JCERSAPublicKey((RSAPublicKey) key);
        }
        if (key instanceof RSAPrivateCrtKey) {
            return new JCERSAPrivateCrtKey((RSAPrivateCrtKey) key);
        }
        if (key instanceof RSAPrivateKey) {
            return new JCERSAPrivateKey((RSAPrivateKey) key);
        }
        if (key instanceof DHPublicKey) {
            if (this.elGamalFactory) {
                return new JCEElGamalPublicKey((DHPublicKey) key);
            }
            return new JCEDHPublicKey((DHPublicKey) key);
        } else if (key instanceof DHPrivateKey) {
            if (this.elGamalFactory) {
                return new JCEElGamalPrivateKey((DHPrivateKey) key);
            }
            return new JCEDHPrivateKey((DHPrivateKey) key);
        } else if (key instanceof DSAPublicKey) {
            return new JDKDSAPublicKey((DSAPublicKey) key);
        } else {
            if (key instanceof DSAPrivateKey) {
                return new JDKDSAPrivateKey((DSAPrivateKey) key);
            }
            if (key instanceof ElGamalPublicKey) {
                return new JCEElGamalPublicKey((ElGamalPublicKey) key);
            }
            if (key instanceof ElGamalPrivateKey) {
                return new JCEElGamalPrivateKey((ElGamalPrivateKey) key);
            }
            throw new InvalidKeyException("key type unknown");
        }
    }

    public static PublicKey createPublicKeyFromDERStream(byte[] in) throws IOException {
        return createPublicKeyFromPublicKeyInfo(new SubjectPublicKeyInfo((ASN1Sequence) ASN1Object.fromByteArray(in)));
    }

    static PublicKey createPublicKeyFromPublicKeyInfo(SubjectPublicKeyInfo info) {
        DERObjectIdentifier algOid = info.getAlgorithmId().getObjectId();
        if (RSAUtil.isRsaOid(algOid)) {
            return new JCERSAPublicKey(info);
        }
        if (algOid.equals(PKCSObjectIdentifiers.dhKeyAgreement)) {
            return new JCEDHPublicKey(info);
        }
        if (algOid.equals(X9ObjectIdentifiers.dhpublicnumber)) {
            return new JCEDHPublicKey(info);
        }
        if (algOid.equals(OIWObjectIdentifiers.elGamalAlgorithm)) {
            return new JCEElGamalPublicKey(info);
        }
        if (algOid.equals(X9ObjectIdentifiers.id_dsa)) {
            return new JDKDSAPublicKey(info);
        }
        if (algOid.equals(OIWObjectIdentifiers.dsaWithSHA1)) {
            return new JDKDSAPublicKey(info);
        }
        if (algOid.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
            return new JCEECPublicKey(info);
        }
        if (algOid.equals(CryptoProObjectIdentifiers.gostR3410_94)) {
            return new JDKGOST3410PublicKey(info);
        }
        if (algOid.equals(CryptoProObjectIdentifiers.gostR3410_2001)) {
            return new JCEECPublicKey(info);
        }
        throw new RuntimeException("algorithm identifier " + algOid + " in key not recognised");
    }

    protected static PrivateKey createPrivateKeyFromDERStream(byte[] in) throws IOException {
        return createPrivateKeyFromPrivateKeyInfo(new PrivateKeyInfo((ASN1Sequence) ASN1Object.fromByteArray(in)));
    }

    static PrivateKey createPrivateKeyFromPrivateKeyInfo(PrivateKeyInfo info) {
        DERObjectIdentifier algOid = info.getAlgorithmId().getObjectId();
        if (RSAUtil.isRsaOid(algOid)) {
            return new JCERSAPrivateCrtKey(info);
        }
        if (algOid.equals(PKCSObjectIdentifiers.dhKeyAgreement)) {
            return new JCEDHPrivateKey(info);
        }
        if (algOid.equals(X9ObjectIdentifiers.dhpublicnumber)) {
            return new JCEDHPrivateKey(info);
        }
        if (algOid.equals(OIWObjectIdentifiers.elGamalAlgorithm)) {
            return new JCEElGamalPrivateKey(info);
        }
        if (algOid.equals(X9ObjectIdentifiers.id_dsa)) {
            return new JDKDSAPrivateKey(info);
        }
        if (algOid.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
            return new JCEECPrivateKey(info);
        }
        if (algOid.equals(CryptoProObjectIdentifiers.gostR3410_94)) {
            return new JDKGOST3410PrivateKey(info);
        }
        if (algOid.equals(CryptoProObjectIdentifiers.gostR3410_2001)) {
            return new JCEECPrivateKey(info);
        }
        throw new RuntimeException("algorithm identifier " + algOid + " in key not recognised");
    }
}
