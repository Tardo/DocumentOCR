package org.spongycastle.jce.provider.asymmetric.ec;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.spongycastle.jce.provider.JCEECPrivateKey;
import org.spongycastle.jce.provider.JCEECPublicKey;
import org.spongycastle.jce.provider.JDKKeyFactory;
import org.spongycastle.jce.provider.ProviderUtil;
import org.spongycastle.jce.spec.ECParameterSpec;

public class KeyFactory extends JDKKeyFactory {
    String algorithm;

    public static class EC extends KeyFactory {
        public EC() {
            super("EC");
        }
    }

    public static class ECDH extends KeyFactory {
        public ECDH() {
            super("ECDH");
        }
    }

    public static class ECDHC extends KeyFactory {
        public ECDHC() {
            super("ECDHC");
        }
    }

    public static class ECDSA extends KeyFactory {
        public ECDSA() {
            super("ECDSA");
        }
    }

    public static class ECGOST3410 extends KeyFactory {
        public ECGOST3410() {
            super("ECGOST3410");
        }
    }

    public static class ECMQV extends KeyFactory {
        public ECMQV() {
            super("ECMQV");
        }
    }

    KeyFactory(String algorithm) {
        this.algorithm = algorithm;
    }

    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof ECPublicKey) {
            return new JCEECPublicKey((ECPublicKey) key);
        }
        if (key instanceof ECPrivateKey) {
            return new JCEECPrivateKey((ECPrivateKey) key);
        }
        throw new InvalidKeyException("key type unknown");
    }

    protected KeySpec engineGetKeySpec(Key key, Class spec) throws InvalidKeySpecException {
        if (spec.isAssignableFrom(PKCS8EncodedKeySpec.class) && key.getFormat().equals("PKCS#8")) {
            return new PKCS8EncodedKeySpec(key.getEncoded());
        }
        if (spec.isAssignableFrom(X509EncodedKeySpec.class) && key.getFormat().equals("X.509")) {
            return new X509EncodedKeySpec(key.getEncoded());
        }
        ECParameterSpec implicitSpec;
        if (spec.isAssignableFrom(ECPublicKeySpec.class) && (key instanceof ECPublicKey)) {
            ECPublicKey k = (ECPublicKey) key;
            if (k.getParams() != null) {
                return new ECPublicKeySpec(k.getW(), k.getParams());
            }
            implicitSpec = ProviderUtil.getEcImplicitlyCa();
            return new ECPublicKeySpec(k.getW(), EC5Util.convertSpec(EC5Util.convertCurve(implicitSpec.getCurve(), implicitSpec.getSeed()), implicitSpec));
        } else if (spec.isAssignableFrom(ECPrivateKeySpec.class) && (key instanceof ECPrivateKey)) {
            ECPrivateKey k2 = (ECPrivateKey) key;
            if (k2.getParams() != null) {
                return new ECPrivateKeySpec(k2.getS(), k2.getParams());
            }
            implicitSpec = ProviderUtil.getEcImplicitlyCa();
            return new ECPrivateKeySpec(k2.getS(), EC5Util.convertSpec(EC5Util.convertCurve(implicitSpec.getCurve(), implicitSpec.getSeed()), implicitSpec));
        } else {
            throw new RuntimeException("not implemented yet " + key + " " + spec);
        }
    }

    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            try {
                return new JCEECPrivateKey(this.algorithm, (JCEECPrivateKey) JDKKeyFactory.createPrivateKeyFromDERStream(((PKCS8EncodedKeySpec) keySpec).getEncoded()));
            } catch (Exception e) {
                throw new InvalidKeySpecException(e.toString());
            }
        } else if (keySpec instanceof org.spongycastle.jce.spec.ECPrivateKeySpec) {
            return new JCEECPrivateKey(this.algorithm, (org.spongycastle.jce.spec.ECPrivateKeySpec) keySpec);
        } else {
            if (keySpec instanceof ECPrivateKeySpec) {
                return new JCEECPrivateKey(this.algorithm, (ECPrivateKeySpec) keySpec);
            }
            throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.getClass().getName());
        }
    }

    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            try {
                return new JCEECPublicKey(this.algorithm, (JCEECPublicKey) JDKKeyFactory.createPublicKeyFromDERStream(((X509EncodedKeySpec) keySpec).getEncoded()));
            } catch (Exception e) {
                throw new InvalidKeySpecException(e.toString());
            }
        } else if (keySpec instanceof org.spongycastle.jce.spec.ECPublicKeySpec) {
            return new JCEECPublicKey(this.algorithm, (org.spongycastle.jce.spec.ECPublicKeySpec) keySpec);
        } else {
            if (keySpec instanceof ECPublicKeySpec) {
                return new JCEECPublicKey(this.algorithm, (ECPublicKeySpec) keySpec);
            }
            throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.getClass().getName());
        }
    }
}
