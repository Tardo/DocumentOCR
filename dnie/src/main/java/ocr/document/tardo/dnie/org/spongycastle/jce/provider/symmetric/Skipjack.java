package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.SkipjackEngine;
import org.spongycastle.crypto.macs.CBCBlockCipherMac;
import org.spongycastle.crypto.macs.CFBBlockCipherMac;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JCEMac;
import org.spongycastle.jce.provider.JDKAlgorithmParameters.IVAlgorithmParameters;

public final class Skipjack {

    public static class Mappings extends HashMap {
        public Mappings() {
            put("Cipher.SKIPJACK", "org.spongycastle.jce.provider.symmetric.Skipjack$ECB");
            put("KeyGenerator.SKIPJACK", "org.spongycastle.jce.provider.symmetric.Skipjack$KeyGen");
            put("AlgorithmParameters.SKIPJACK", "org.spongycastle.jce.provider.symmetric.Skipjack$AlgParams");
            put("Mac.SKIPJACKMAC", "org.spongycastle.jce.provider.symmetric.Skipjack$Mac");
            put("Alg.Alias.Mac.SKIPJACK", "SKIPJACKMAC");
            put("Mac.SKIPJACKMAC/CFB8", "org.spongycastle.jce.provider.symmetric.Skipjack$MacCFB8");
            put("Alg.Alias.Mac.SKIPJACK/CFB8", "SKIPJACKMAC/CFB8");
        }
    }

    public static class KeyGen extends JCEKeyGenerator {
        public KeyGen() {
            super("Skipjack", 80, new CipherKeyGenerator());
        }
    }

    public static class AlgParams extends IVAlgorithmParameters {
        protected String engineToString() {
            return "Skipjack IV";
        }
    }

    public static class Mac extends JCEMac {
        public Mac() {
            super(new CBCBlockCipherMac(new SkipjackEngine()));
        }
    }

    public static class MacCFB8 extends JCEMac {
        public MacCFB8() {
            super(new CFBBlockCipherMac(new SkipjackEngine()));
        }
    }

    public static class ECB extends JCEBlockCipher {
        public ECB() {
            super(new SkipjackEngine());
        }
    }

    private Skipjack() {
    }
}