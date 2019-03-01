package org.spongycastle.jce.provider.symmetric;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.spongycastle.asn1.oiw.OIWObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.crypto.KeyGenerationParameters;
import org.spongycastle.crypto.engines.DESedeEngine;
import org.spongycastle.crypto.engines.DESedeWrapEngine;
import org.spongycastle.crypto.engines.RFC3211WrapEngine;
import org.spongycastle.crypto.generators.DESedeKeyGenerator;
import org.spongycastle.crypto.macs.CBCBlockCipherMac;
import org.spongycastle.crypto.macs.CFBBlockCipherMac;
import org.spongycastle.crypto.macs.CMac;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JCEMac;
import org.spongycastle.jce.provider.JCESecretKeyFactory;
import org.spongycastle.jce.provider.WrapCipherSpi;

public final class DESede {

    public static class Mappings extends HashMap {
        public Mappings() {
            put("Cipher.DESEDE", "org.spongycastle.jce.provider.symmetric.DESede$ECB");
            put("Cipher." + PKCSObjectIdentifiers.des_EDE3_CBC, "org.spongycastle.jce.provider.symmetric.DESede$CBC");
            put("Cipher." + OIWObjectIdentifiers.desCBC, "org.spongycastle.jce.provider.symmetric.DESede$CBC");
            put("Cipher.DESEDEWRAP", "org.spongycastle.jce.provider.symmetric.DESede$Wrap");
            put("Cipher." + PKCSObjectIdentifiers.id_alg_CMS3DESwrap, "org.spongycastle.jce.provider.symmetric.DESede$Wrap");
            put("Cipher.DESEDERFC3211WRAP", "org.spongycastle.jce.provider.symmetric.DESede$RFC3211");
            put("KeyGenerator.DESEDE", "org.spongycastle.jce.provider.symmetric.DESede$KeyGenerator");
            put("KeyGenerator." + PKCSObjectIdentifiers.des_EDE3_CBC, "org.spongycastle.jce.provider.symmetric.DESede$KeyGenerator3");
            put("KeyGenerator.DESEDEWRAP", "org.spongycastle.jce.provider.symmetric.DESede$KeyGenerator");
            put("SecretKeyFactory.DESEDE", "org.spongycastle.jce.provider.symmetric.DESede$KeyFactory");
            put("Mac.DESEDECMAC", "org.spongycastle.jce.provider.symmetric.DESede$CMAC");
            put("Mac.DESEDEMAC", "org.spongycastle.jce.provider.symmetric.DESede$CBCMAC");
            put("Alg.Alias.Mac.DESEDE", "DESEDEMAC");
            put("Mac.DESEDEMAC/CFB8", "org.spongycastle.jce.provider.symmetric.DESede$DESedeCFB8");
            put("Alg.Alias.Mac.DESEDE/CFB8", "DESEDEMAC/CFB8");
            put("Mac.DESEDEMAC64", "org.spongycastle.jce.provider.symmetric.DESede$DESede64");
            put("Alg.Alias.Mac.DESEDE64", "DESEDEMAC64");
            put("Mac.DESEDEMAC64WITHISO7816-4PADDING", "org.spongycastle.jce.provider.symmetric.DESede$DESede64with7816d4");
            put("Alg.Alias.Mac.DESEDE64WITHISO7816-4PADDING", "DESEDEMAC64WITHISO7816-4PADDING");
            put("Alg.Alias.Mac.DESEDEISO9797ALG1MACWITHISO7816-4PADDING", "DESEDEMAC64WITHISO7816-4PADDING");
            put("Alg.Alias.Mac.DESEDEISO9797ALG1WITHISO7816-4PADDING", "DESEDEMAC64WITHISO7816-4PADDING");
        }
    }

    public static class KeyGenerator3 extends JCEKeyGenerator {
        public KeyGenerator3() {
            super("DESede3", 192, new DESedeKeyGenerator());
        }
    }

    public static class KeyGenerator extends JCEKeyGenerator {
        private boolean keySizeSet = false;

        public KeyGenerator() {
            super("DESede", 192, new DESedeKeyGenerator());
        }

        protected void engineInit(int keySize, SecureRandom random) {
            super.engineInit(keySize, random);
            this.keySizeSet = true;
        }

        protected SecretKey engineGenerateKey() {
            if (this.uninitialised) {
                this.engine.init(new KeyGenerationParameters(new SecureRandom(), this.defaultKeySize));
                this.uninitialised = false;
            }
            if (this.keySizeSet) {
                return new SecretKeySpec(this.engine.generateKey(), this.algName);
            }
            byte[] k = this.engine.generateKey();
            System.arraycopy(k, 0, k, 16, 8);
            return new SecretKeySpec(k, this.algName);
        }
    }

    public static class CBCMAC extends JCEMac {
        public CBCMAC() {
            super(new CBCBlockCipherMac(new DESedeEngine()));
        }
    }

    public static class CMAC extends JCEMac {
        public CMAC() {
            super(new CMac(new DESedeEngine()));
        }
    }

    public static class DESede64 extends JCEMac {
        public DESede64() {
            super(new CBCBlockCipherMac(new DESedeEngine(), 64));
        }
    }

    public static class DESede64with7816d4 extends JCEMac {
        public DESede64with7816d4() {
            super(new CBCBlockCipherMac(new DESedeEngine(), 64, new ISO7816d4Padding()));
        }
    }

    public static class DESedeCFB8 extends JCEMac {
        public DESedeCFB8() {
            super(new CFBBlockCipherMac(new DESedeEngine()));
        }
    }

    public static class KeyFactory extends JCESecretKeyFactory {
        public KeyFactory() {
            super("DESede", null);
        }

        protected KeySpec engineGetKeySpec(SecretKey key, Class keySpec) throws InvalidKeySpecException {
            if (keySpec == null) {
                throw new InvalidKeySpecException("keySpec parameter is null");
            } else if (key == null) {
                throw new InvalidKeySpecException("key parameter is null");
            } else if (SecretKeySpec.class.isAssignableFrom(keySpec)) {
                return new SecretKeySpec(key.getEncoded(), this.algName);
            } else {
                if (DESedeKeySpec.class.isAssignableFrom(keySpec)) {
                    byte[] bytes = key.getEncoded();
                    try {
                        if (bytes.length != 16) {
                            return new DESedeKeySpec(bytes);
                        }
                        byte[] longKey = new byte[24];
                        System.arraycopy(bytes, 0, longKey, 0, 16);
                        System.arraycopy(bytes, 0, longKey, 16, 8);
                        return new DESedeKeySpec(longKey);
                    } catch (Exception e) {
                        throw new InvalidKeySpecException(e.toString());
                    }
                }
                throw new InvalidKeySpecException("Invalid KeySpec");
            }
        }

        protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof DESedeKeySpec) {
                return new SecretKeySpec(((DESedeKeySpec) keySpec).getKey(), "DESede");
            }
            return super.engineGenerateSecret(keySpec);
        }
    }

    public static class RFC3211 extends WrapCipherSpi {
        public RFC3211() {
            super(new RFC3211WrapEngine(new DESedeEngine()), 8);
        }
    }

    public static class Wrap extends WrapCipherSpi {
        public Wrap() {
            super(new DESedeWrapEngine());
        }
    }

    public static class CBC extends JCEBlockCipher {
        public CBC() {
            super(new CBCBlockCipher(new DESedeEngine()), 64);
        }
    }

    public static class ECB extends JCEBlockCipher {
        public ECB() {
            super(new DESedeEngine());
        }
    }

    private DESede() {
    }
}
