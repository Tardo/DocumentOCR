package org.spongycastle.jce.provider;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.digests.MD5Digest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.generators.PKCS12ParametersGenerator;
import org.spongycastle.crypto.generators.PKCS5S1ParametersGenerator;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

public interface BrokenPBE {
    public static final int MD5 = 0;
    public static final int OLD_PKCS12 = 3;
    public static final int PKCS12 = 2;
    public static final int PKCS5S1 = 0;
    public static final int PKCS5S2 = 1;
    public static final int RIPEMD160 = 2;
    public static final int SHA1 = 1;

    public static class Util {
        private static void setOddParity(byte[] bytes) {
            for (int i = 0; i < bytes.length; i++) {
                int b = bytes[i];
                bytes[i] = (byte) ((b & 254) | ((((((((b >> 1) ^ (b >> 2)) ^ (b >> 3)) ^ (b >> 4)) ^ (b >> 5)) ^ (b >> 6)) ^ (b >> 7)) ^ 1));
            }
        }

        private static PBEParametersGenerator makePBEGenerator(int type, int hash) {
            if (type == 0) {
                switch (hash) {
                    case 0:
                        return new PKCS5S1ParametersGenerator(new MD5Digest());
                    case 1:
                        return new PKCS5S1ParametersGenerator(new SHA1Digest());
                    default:
                        throw new IllegalStateException("PKCS5 scheme 1 only supports only MD5 and SHA1.");
                }
            } else if (type == 1) {
                return new PKCS5S2ParametersGenerator();
            } else {
                if (type == 3) {
                    switch (hash) {
                        case 0:
                            return new OldPKCS12ParametersGenerator(new MD5Digest());
                        case 1:
                            return new OldPKCS12ParametersGenerator(new SHA1Digest());
                        case 2:
                            return new OldPKCS12ParametersGenerator(new RIPEMD160Digest());
                        default:
                            throw new IllegalStateException("unknown digest scheme for PBE encryption.");
                    }
                }
                switch (hash) {
                    case 0:
                        return new PKCS12ParametersGenerator(new MD5Digest());
                    case 1:
                        return new PKCS12ParametersGenerator(new SHA1Digest());
                    case 2:
                        return new PKCS12ParametersGenerator(new RIPEMD160Digest());
                    default:
                        throw new IllegalStateException("unknown digest scheme for PBE encryption.");
                }
            }
        }

        static CipherParameters makePBEParameters(JCEPBEKey pbeKey, AlgorithmParameterSpec spec, int type, int hash, String targetAlgorithm, int keySize, int ivSize) {
            if (spec == null || !(spec instanceof PBEParameterSpec)) {
                throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
            }
            CipherParameters param;
            PBEParameterSpec pbeParam = (PBEParameterSpec) spec;
            PBEParametersGenerator generator = makePBEGenerator(type, hash);
            byte[] key = pbeKey.getEncoded();
            generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());
            if (ivSize != 0) {
                param = generator.generateDerivedParameters(keySize, ivSize);
            } else {
                param = generator.generateDerivedParameters(keySize);
            }
            if (targetAlgorithm.startsWith("DES")) {
                if (param instanceof ParametersWithIV) {
                    setOddParity(((KeyParameter) ((ParametersWithIV) param).getParameters()).getKey());
                } else {
                    setOddParity(((KeyParameter) param).getKey());
                }
            }
            for (int i = 0; i != key.length; i++) {
                key[i] = (byte) 0;
            }
            return param;
        }

        static CipherParameters makePBEMacParameters(JCEPBEKey pbeKey, AlgorithmParameterSpec spec, int type, int hash, int keySize) {
            if (spec == null || !(spec instanceof PBEParameterSpec)) {
                throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
            }
            PBEParameterSpec pbeParam = (PBEParameterSpec) spec;
            PBEParametersGenerator generator = makePBEGenerator(type, hash);
            byte[] key = pbeKey.getEncoded();
            generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());
            CipherParameters param = generator.generateDerivedMacParameters(keySize);
            for (int i = 0; i != key.length; i++) {
                key[i] = (byte) 0;
            }
            return param;
        }
    }
}
