package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.RijndaelEngine;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameters.IVAlgorithmParameters;

public final class Rijndael {

    public static class Mappings extends HashMap {
        public Mappings() {
            put("Cipher.RIJNDAEL", "org.spongycastle.jce.provider.symmetric.Rijndael$ECB");
            put("KeyGenerator.RIJNDAEL", "org.spongycastle.jce.provider.symmetric.Rijndael$KeyGen");
            put("AlgorithmParameters.RIJNDAEL", "org.spongycastle.jce.provider.symmetric.Rijndael$AlgParams");
        }
    }

    public static class KeyGen extends JCEKeyGenerator {
        public KeyGen() {
            super("Rijndael", 192, new CipherKeyGenerator());
        }
    }

    public static class AlgParams extends IVAlgorithmParameters {
        protected String engineToString() {
            return "Rijndael IV";
        }
    }

    public static class ECB extends JCEBlockCipher {
        public ECB() {
            super(new RijndaelEngine());
        }
    }

    private Rijndael() {
    }
}
