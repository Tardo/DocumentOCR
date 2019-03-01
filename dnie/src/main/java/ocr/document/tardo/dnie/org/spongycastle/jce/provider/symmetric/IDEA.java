package org.spongycastle.jce.provider.symmetric;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import javax.crypto.spec.IvParameterSpec;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.misc.IDEACBCPar;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.IDEAEngine;
import org.spongycastle.crypto.macs.CBCBlockCipherMac;
import org.spongycastle.crypto.macs.CFBBlockCipherMac;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JCEMac;
import org.spongycastle.jce.provider.JCESecretKeyFactory.PBEKeyFactory;
import org.spongycastle.jce.provider.JDKAlgorithmParameterGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameters;

public final class IDEA {

    public static class Mappings extends HashMap {
        public Mappings() {
            put("AlgorithmParameterGenerator.IDEA", "org.spongycastle.jce.provider.symmetric.IDEA$AlgParamGen");
            put("AlgorithmParameterGenerator.1.3.6.1.4.1.188.7.1.1.2", "org.spongycastle.jce.provider.symmetric.IDEA$AlgParamGen");
            put("AlgorithmParameters.IDEA", "org.spongycastle.jce.provider.symmetric.IDEA$AlgParams");
            put("AlgorithmParameters.1.3.6.1.4.1.188.7.1.1.2", "org.spongycastle.jce.provider.symmetric.IDEA$AlgParams");
            put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDIDEA", "PKCS12PBE");
            put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDIDEA", "PKCS12PBE");
            put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDIDEA-CBC", "PKCS12PBE");
            put("Cipher.IDEA", "org.spongycastle.jce.provider.symmetric.IDEA$ECB");
            put("Cipher.1.3.6.1.4.1.188.7.1.1.2", "org.spongycastle.jce.provider.symmetric.IDEA$CBC");
            put("Cipher.PBEWITHSHAANDIDEA-CBC", "org.spongycastle.jce.provider.symmetric.IDEA$PBEWithSHAAndIDEA");
            put("KeyGenerator.IDEA", "org.spongycastle.jce.provider.symmetric.IDEA$KeyGen");
            put("KeyGenerator.1.3.6.1.4.1.188.7.1.1.2", "org.spongycastle.jce.provider.symmetric.IDEA$KeyGen");
            put("SecretKeyFactory.PBEWITHSHAANDIDEA-CBC", "org.spongycastle.jce.provider.symmetric.IDEA$PBEWithSHAAndIDEAKeyGen");
            put("Mac.IDEAMAC", "org.spongycastle.jce.provider.symmetric.IDEA$Mac");
            put("Alg.Alias.Mac.IDEA", "IDEAMAC");
            put("Mac.IDEAMAC/CFB8", "org.spongycastle.jce.provider.symmetric.IDEA$CFB8Mac");
            put("Alg.Alias.Mac.IDEA/CFB8", "IDEAMAC/CFB8");
        }
    }

    public static class AlgParamGen extends JDKAlgorithmParameterGenerator {
        protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for IDEA parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters() {
            byte[] iv = new byte[8];
            if (this.random == null) {
                this.random = new SecureRandom();
            }
            this.random.nextBytes(iv);
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("IDEA", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new IvParameterSpec(iv));
                return params;
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    public static class AlgParams extends JDKAlgorithmParameters {
        private byte[] iv;

        protected byte[] engineGetEncoded() throws IOException {
            return engineGetEncoded("ASN.1");
        }

        protected byte[] engineGetEncoded(String format) throws IOException {
            if (isASN1FormatString(format)) {
                return new IDEACBCPar(engineGetEncoded("RAW")).getEncoded();
            }
            if (!format.equals("RAW")) {
                return null;
            }
            byte[] tmp = new byte[this.iv.length];
            System.arraycopy(this.iv, 0, tmp, 0, this.iv.length);
            return tmp;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == IvParameterSpec.class) {
                return new IvParameterSpec(this.iv);
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to IV parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof IvParameterSpec) {
                this.iv = ((IvParameterSpec) paramSpec).getIV();
                return;
            }
            throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
        }

        protected void engineInit(byte[] params) throws IOException {
            this.iv = new byte[params.length];
            System.arraycopy(params, 0, this.iv, 0, this.iv.length);
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (format.equals("RAW")) {
                engineInit(params);
            } else if (format.equals("ASN.1")) {
                engineInit(new IDEACBCPar((ASN1Sequence) new ASN1InputStream(params).readObject()).getIV());
            } else {
                throw new IOException("Unknown parameters format in IV parameters object");
            }
        }

        protected String engineToString() {
            return "IDEA Parameters";
        }
    }

    public static class KeyGen extends JCEKeyGenerator {
        public KeyGen() {
            super("IDEA", 128, new CipherKeyGenerator());
        }
    }

    public static class CFB8Mac extends JCEMac {
        public CFB8Mac() {
            super(new CFBBlockCipherMac(new IDEAEngine()));
        }
    }

    public static class Mac extends JCEMac {
        public Mac() {
            super(new CBCBlockCipherMac(new IDEAEngine()));
        }
    }

    public static class CBC extends JCEBlockCipher {
        public CBC() {
            super(new CBCBlockCipher(new IDEAEngine()), 64);
        }
    }

    public static class ECB extends JCEBlockCipher {
        public ECB() {
            super(new IDEAEngine());
        }
    }

    public static class PBEWithSHAAndIDEA extends JCEBlockCipher {
        public PBEWithSHAAndIDEA() {
            super(new CBCBlockCipher(new IDEAEngine()));
        }
    }

    public static class PBEWithSHAAndIDEAKeyGen extends PBEKeyFactory {
        public PBEWithSHAAndIDEAKeyGen() {
            super("PBEwithSHAandIDEA-CBC", null, true, 2, 1, 128, 64);
        }
    }

    private IDEA() {
    }
}
