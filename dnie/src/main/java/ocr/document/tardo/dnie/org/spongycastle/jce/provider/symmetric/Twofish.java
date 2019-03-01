package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.TwofishEngine;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameters.IVAlgorithmParameters;

public final class Twofish {

    public static class Mappings extends HashMap {
        public Mappings() {
            put("Cipher.Twofish", "org.spongycastle.jce.provider.symmetric.Twofish$ECB");
            put("KeyGenerator.Twofish", "org.spongycastle.jce.provider.symmetric.Twofish$KeyGen");
            put("AlgorithmParameters.Twofish", "org.spongycastle.jce.provider.symmetric.Twofish$AlgParams");
        }
    }

    public static class KeyGen extends JCEKeyGenerator {
        public KeyGen() {
            super("Twofish", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParams extends IVAlgorithmParameters {
        protected String engineToString() {
            return "Twofish IV";
        }
    }

    public static class ECB extends JCEBlockCipher {
        public ECB() {
            super(new TwofishEngine());
        }
    }

    private Twofish() {
    }
}
