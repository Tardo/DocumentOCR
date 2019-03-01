package custom.org.apache.harmony.security.provider.crypto;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class DSAKeyFactoryImpl extends KeyFactorySpi {
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec != null) {
            if (keySpec instanceof DSAPrivateKeySpec) {
                return new DSAPrivateKeyImpl((DSAPrivateKeySpec) keySpec);
            }
            if (keySpec instanceof PKCS8EncodedKeySpec) {
                return new DSAPrivateKeyImpl((PKCS8EncodedKeySpec) keySpec);
            }
        }
        throw new InvalidKeySpecException(Messages.getString("security.19C"));
    }

    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec != null) {
            if (keySpec instanceof DSAPublicKeySpec) {
                return new DSAPublicKeyImpl((DSAPublicKeySpec) keySpec);
            }
            if (keySpec instanceof X509EncodedKeySpec) {
                return new DSAPublicKeyImpl((X509EncodedKeySpec) keySpec);
            }
        }
        throw new InvalidKeySpecException(Messages.getString("security.19D"));
    }

    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (key != null) {
            if (keySpec == null) {
                throw new NullPointerException(Messages.getString("security.19E"));
            } else if (key instanceof DSAPrivateKey) {
                DSAPrivateKey privateKey = (DSAPrivateKey) key;
                if (keySpec.equals(DSAPrivateKeySpec.class)) {
                    BigInteger x = privateKey.getX();
                    params = privateKey.getParams();
                    return new DSAPrivateKeySpec(x, params.getP(), params.getQ(), params.getG());
                } else if (keySpec.equals(PKCS8EncodedKeySpec.class)) {
                    return new PKCS8EncodedKeySpec(key.getEncoded());
                } else {
                    throw new InvalidKeySpecException(Messages.getString("security.19C"));
                }
            } else if (key instanceof DSAPublicKey) {
                DSAPublicKey publicKey = (DSAPublicKey) key;
                if (keySpec.equals(DSAPublicKeySpec.class)) {
                    BigInteger y = publicKey.getY();
                    params = publicKey.getParams();
                    return new DSAPublicKeySpec(y, params.getP(), params.getQ(), params.getG());
                } else if (keySpec.equals(X509EncodedKeySpec.class)) {
                    return new X509EncodedKeySpec(key.getEncoded());
                } else {
                    throw new InvalidKeySpecException(Messages.getString("security.19D"));
                }
            }
        }
        throw new InvalidKeySpecException(Messages.getString("security.19F"));
    }

    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key != null) {
            Key engineGeneratePrivate;
            DSAParams params;
            if (key instanceof DSAPrivateKey) {
                DSAPrivateKey privateKey = (DSAPrivateKey) key;
                params = privateKey.getParams();
                try {
                    engineGeneratePrivate = engineGeneratePrivate(new DSAPrivateKeySpec(privateKey.getX(), params.getP(), params.getQ(), params.getG()));
                } catch (Object e) {
                    throw new InvalidKeyException(Messages.getString("security.1A0", e));
                }
            } else if (key instanceof DSAPublicKey) {
                DSAPublicKey publicKey = (DSAPublicKey) key;
                params = publicKey.getParams();
                try {
                    engineGeneratePrivate = engineGeneratePublic(new DSAPublicKeySpec(publicKey.getY(), params.getP(), params.getQ(), params.getG()));
                } catch (Object e2) {
                    throw new InvalidKeyException(Messages.getString("security.1A1", e2));
                }
            }
            return engineGeneratePrivate;
        }
        throw new InvalidKeyException(Messages.getString("security.19F"));
    }
}
