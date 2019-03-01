package org.spongycastle.jce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import javax.crypto.spec.IvParameterSpec;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.RC532Engine;
import org.spongycastle.crypto.engines.RC564Engine;
import org.spongycastle.crypto.macs.CBCBlockCipherMac;
import org.spongycastle.crypto.macs.CFBBlockCipherMac;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JCEMac;
import org.spongycastle.jce.provider.JDKAlgorithmParameterGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameters.IVAlgorithmParameters;

public final class RC5 {

    public static class Mappings extends HashMap {
        public Mappings() {
            put("Cipher.RC5", "org.spongycastle.jce.provider.symmetric.RC5$ECB32");
            put("Alg.Alias.Cipher.RC5-32", "RC5");
            put("Cipher.RC5-64", "org.spongycastle.jce.provider.symmetric.RC5$ECB64");
            put("KeyGenerator.RC5", "org.spongycastle.jce.provider.symmetric.RC5$KeyGen32");
            put("Alg.Alias.KeyGenerator.RC5-32", "RC5");
            put("KeyGenerator.RC5-64", "org.spongycastle.jce.provider.symmetric.RC5$KeyGen64");
            put("AlgorithmParameters.RC5", "org.spongycastle.jce.provider.symmetric.RC5$AlgParams");
            put("AlgorithmParameters.RC5-64", "org.spongycastle.jce.provider.symmetric.RC5$AlgParams");
            put("Mac.RC5MAC", "org.spongycastle.jce.provider.symmetric.RC5$Mac32");
            put("Alg.Alias.Mac.RC5", "RC5MAC");
            put("Mac.RC5MAC/CFB8", "org.spongycastle.jce.provider.symmetric.RC5$CFB8Mac32");
            put("Alg.Alias.Mac.RC5/CFB8", "RC5MAC/CFB8");
        }
    }

    public static class AlgParamGen extends JDKAlgorithmParameterGenerator {
        protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for RC5 parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters() {
            byte[] iv = new byte[8];
            if (this.random == null) {
                this.random = new SecureRandom();
            }
            this.random.nextBytes(iv);
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("RC5", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new IvParameterSpec(iv));
                return params;
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    public static class KeyGen32 extends JCEKeyGenerator {
        public KeyGen32() {
            super("RC5", 128, new CipherKeyGenerator());
        }
    }

    public static class KeyGen64 extends JCEKeyGenerator {
        public KeyGen64() {
            super("RC5-64", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParams extends IVAlgorithmParameters {
        protected String engineToString() {
            return "RC5 IV";
        }
    }

    public static class CFB8Mac32 extends JCEMac {
        public CFB8Mac32() {
            super(new CFBBlockCipherMac(new RC532Engine()));
        }
    }

    public static class Mac32 extends JCEMac {
        public Mac32() {
            super(new CBCBlockCipherMac(new RC532Engine()));
        }
    }

    public static class CBC32 extends JCEBlockCipher {
        public CBC32() {
            super(new CBCBlockCipher(new RC532Engine()), 64);
        }
    }

    public static class ECB32 extends JCEBlockCipher {
        public ECB32() {
            super(new RC532Engine());
        }
    }

    public static class ECB64 extends JCEBlockCipher {
        public ECB64() {
            super(new RC564Engine());
        }
    }

    private RC5() {
    }
}