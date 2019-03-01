package org.spongycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.KeyGenerationParameters;
import org.spongycastle.crypto.generators.DESKeyGenerator;

public class JCEKeyGenerator extends KeyGeneratorSpi {
    protected String algName;
    protected int defaultKeySize;
    protected CipherKeyGenerator engine;
    protected int keySize;
    protected boolean uninitialised = true;

    public static class DES extends JCEKeyGenerator {
        public DES() {
            super("DES", 64, new DESKeyGenerator());
        }
    }

    public static class GOST28147 extends JCEKeyGenerator {
        public GOST28147() {
            super("GOST28147", 256, new CipherKeyGenerator());
        }
    }

    public static class HMACSHA1 extends JCEKeyGenerator {
        public HMACSHA1() {
            super("HMACSHA1", CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, new CipherKeyGenerator());
        }
    }

    public static class HMACSHA224 extends JCEKeyGenerator {
        public HMACSHA224() {
            super("HMACSHA224", 224, new CipherKeyGenerator());
        }
    }

    public static class HMACSHA256 extends JCEKeyGenerator {
        public HMACSHA256() {
            super("HMACSHA256", 256, new CipherKeyGenerator());
        }
    }

    public static class HMACSHA384 extends JCEKeyGenerator {
        public HMACSHA384() {
            super("HMACSHA384", 384, new CipherKeyGenerator());
        }
    }

    public static class HMACSHA512 extends JCEKeyGenerator {
        public HMACSHA512() {
            super("HMACSHA512", 512, new CipherKeyGenerator());
        }
    }

    public static class HMACTIGER extends JCEKeyGenerator {
        public HMACTIGER() {
            super("HMACTIGER", 192, new CipherKeyGenerator());
        }
    }

    public static class MD2HMAC extends JCEKeyGenerator {
        public MD2HMAC() {
            super("HMACMD2", 128, new CipherKeyGenerator());
        }
    }

    public static class MD4HMAC extends JCEKeyGenerator {
        public MD4HMAC() {
            super("HMACMD4", 128, new CipherKeyGenerator());
        }
    }

    public static class MD5HMAC extends JCEKeyGenerator {
        public MD5HMAC() {
            super("HMACMD5", 128, new CipherKeyGenerator());
        }
    }

    public static class RC2 extends JCEKeyGenerator {
        public RC2() {
            super("RC2", 128, new CipherKeyGenerator());
        }
    }

    public static class RIPEMD128HMAC extends JCEKeyGenerator {
        public RIPEMD128HMAC() {
            super("HMACRIPEMD128", 128, new CipherKeyGenerator());
        }
    }

    public static class RIPEMD160HMAC extends JCEKeyGenerator {
        public RIPEMD160HMAC() {
            super("HMACRIPEMD160", CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, new CipherKeyGenerator());
        }
    }

    protected JCEKeyGenerator(String algName, int defaultKeySize, CipherKeyGenerator engine) {
        this.algName = algName;
        this.defaultKeySize = defaultKeySize;
        this.keySize = defaultKeySize;
        this.engine = engine;
    }

    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("Not Implemented");
    }

    protected void engineInit(SecureRandom random) {
        if (random != null) {
            this.engine.init(new KeyGenerationParameters(random, this.defaultKeySize));
            this.uninitialised = false;
        }
    }

    protected void engineInit(int keySize, SecureRandom random) {
        try {
            this.engine.init(new KeyGenerationParameters(random, keySize));
            this.uninitialised = false;
        } catch (IllegalArgumentException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    protected SecretKey engineGenerateKey() {
        if (this.uninitialised) {
            this.engine.init(new KeyGenerationParameters(new SecureRandom(), this.defaultKeySize));
            this.uninitialised = false;
        }
        return new SecretKeySpec(this.engine.generateKey(), this.algName);
    }
}
