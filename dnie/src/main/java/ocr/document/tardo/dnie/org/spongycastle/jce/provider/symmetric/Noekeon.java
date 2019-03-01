package org.spongycastle.jce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import javax.crypto.spec.IvParameterSpec;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.NoekeonEngine;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameterGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameters.IVAlgorithmParameters;

public final class Noekeon {

    public static class Mappings extends HashMap {
        public Mappings() {
            put("AlgorithmParameters.NOEKEON", "org.spongycastle.jce.provider.symmetric.Noekeon$AlgParams");
            put("AlgorithmParameterGenerator.NOEKEON", "org.spongycastle.jce.provider.symmetric.Noekeon$AlgParamGen");
            put("Cipher.NOEKEON", "org.spongycastle.jce.provider.symmetric.Noekeon$ECB");
            put("KeyGenerator.NOEKEON", "org.spongycastle.jce.provider.symmetric.Noekeon$KeyGen");
        }
    }

    public static class AlgParamGen extends JDKAlgorithmParameterGenerator {
        protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for Noekeon parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters() {
            byte[] iv = new byte[16];
            if (this.random == null) {
                this.random = new SecureRandom();
            }
            this.random.nextBytes(iv);
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("Noekeon", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new IvParameterSpec(iv));
                return params;
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    public static class KeyGen extends JCEKeyGenerator {
        public KeyGen() {
            super("Noekeon", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParams extends IVAlgorithmParameters {
        protected String engineToString() {
            return "Noekeon IV";
        }
    }

    public static class ECB extends JCEBlockCipher {
        public ECB() {
            super(new NoekeonEngine());
        }
    }

    private Noekeon() {
    }
}
