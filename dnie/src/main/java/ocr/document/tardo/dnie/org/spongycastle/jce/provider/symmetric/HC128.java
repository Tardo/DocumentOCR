package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.HC128Engine;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JCEStreamCipher;

public final class HC128 {

    public static class Mappings extends HashMap {
        public Mappings() {
            put("Cipher.HC128", "org.spongycastle.jce.provider.symmetric.HC128$Base");
            put("KeyGenerator.HC128", "org.spongycastle.jce.provider.symmetric.HC128$KeyGen");
        }
    }

    public static class KeyGen extends JCEKeyGenerator {
        public KeyGen() {
            super("HC128", 128, new CipherKeyGenerator());
        }
    }

    public static class Base extends JCEStreamCipher {
        public Base() {
            super(new HC128Engine(), 16);
        }
    }

    private HC128() {
    }
}