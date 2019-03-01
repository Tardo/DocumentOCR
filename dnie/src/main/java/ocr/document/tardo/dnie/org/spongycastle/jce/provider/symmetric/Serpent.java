package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.SerpentEngine;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameters.IVAlgorithmParameters;

public final class Serpent {

    public static class Mappings extends HashMap {
        public Mappings() {
            put("Cipher.Serpent", "org.spongycastle.jce.provider.symmetric.Serpent$ECB");
            put("KeyGenerator.Serpent", "org.spongycastle.jce.provider.symmetric.Serpent$KeyGen");
            put("AlgorithmParameters.Serpent", "org.spongycastle.jce.provider.symmetric.Serpent$AlgParams");
        }
    }

    public static class KeyGen extends JCEKeyGenerator {
        public KeyGen() {
            super("Serpent", 192, new CipherKeyGenerator());
        }
    }

    public static class AlgParams extends IVAlgorithmParameters {
        protected String engineToString() {
            return "Serpent IV";
        }
    }

    public static class ECB extends JCEBlockCipher {
        public ECB() {
            super(new SerpentEngine());
        }
    }

    private Serpent() {
    }
}
