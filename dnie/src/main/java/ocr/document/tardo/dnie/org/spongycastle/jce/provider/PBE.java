package org.spongycastle.jce.provider;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.digests.MD2Digest;
import org.spongycastle.crypto.digests.MD5Digest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.TigerDigest;
import org.spongycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.spongycastle.crypto.generators.PKCS12ParametersGenerator;
import org.spongycastle.crypto.generators.PKCS5S1ParametersGenerator;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.DESParameters;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

public interface PBE {
    public static final int MD2 = 5;
    public static final int MD5 = 0;
    public static final int OPENSSL = 3;
    public static final int PKCS12 = 2;
    public static final int PKCS5S1 = 0;
    public static final int PKCS5S2 = 1;
    public static final int RIPEMD160 = 2;
    public static final int SHA1 = 1;
    public static final int SHA256 = 4;
    public static final int TIGER = 3;

    public static class Util {
        private static PBEParametersGenerator makePBEGenerator(int type, int hash) {
            if (type == 0) {
                switch (hash) {
                    case 0:
                        return new PKCS5S1ParametersGenerator(new MD5Digest());
                    case 1:
                        return new PKCS5S1ParametersGenerator(new SHA1Digest());
                    case 5:
                        return new PKCS5S1ParametersGenerator(new MD2Digest());
                    default:
                        throw new IllegalStateException("PKCS5 scheme 1 only supports MD2, MD5 and SHA1.");
                }
            } else if (type == 1) {
                return new PKCS5S2ParametersGenerator();
            } else {
                if (type != 2) {
                    return new OpenSSLPBEParametersGenerator();
                }
                switch (hash) {
                    case 0:
                        return new PKCS12ParametersGenerator(new MD5Digest());
                    case 1:
                        return new PKCS12ParametersGenerator(new SHA1Digest());
                    case 2:
                        return new PKCS12ParametersGenerator(new RIPEMD160Digest());
                    case 3:
                        return new PKCS12ParametersGenerator(new TigerDigest());
                    case 4:
                        return new PKCS12ParametersGenerator(new SHA256Digest());
                    case 5:
                        return new PKCS12ParametersGenerator(new MD2Digest());
                    default:
                        throw new IllegalStateException("unknown digest scheme for PBE encryption.");
                }
            }
        }

        static CipherParameters makePBEParameters(JCEPBEKey pbeKey, AlgorithmParameterSpec spec, String targetAlgorithm) {
            if (spec == null || !(spec instanceof PBEParameterSpec)) {
                throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
            }
            CipherParameters param;
            PBEParameterSpec pbeParam = (PBEParameterSpec) spec;
            PBEParametersGenerator generator = makePBEGenerator(pbeKey.getType(), pbeKey.getDigest());
            byte[] key = pbeKey.getEncoded();
            if (pbeKey.shouldTryWrongPKCS12()) {
                key = new byte[2];
            }
            generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());
            if (pbeKey.getIvSize() != 0) {
                param = generator.generateDerivedParameters(pbeKey.getKeySize(), pbeKey.getIvSize());
            } else {
                param = generator.generateDerivedParameters(pbeKey.getKeySize());
            }
            if (targetAlgorithm.startsWith("DES")) {
                if (param instanceof ParametersWithIV) {
                    DESParameters.setOddParity(((KeyParameter) ((ParametersWithIV) param).getParameters()).getKey());
                } else {
                    DESParameters.setOddParity(((KeyParameter) param).getKey());
                }
            }
            for (int i = 0; i != key.length; i++) {
                key[i] = (byte) 0;
            }
            return param;
        }

        static CipherParameters makePBEMacParameters(JCEPBEKey pbeKey, AlgorithmParameterSpec spec) {
            if (spec == null || !(spec instanceof PBEParameterSpec)) {
                throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
            }
            PBEParameterSpec pbeParam = (PBEParameterSpec) spec;
            PBEParametersGenerator generator = makePBEGenerator(pbeKey.getType(), pbeKey.getDigest());
            byte[] key = pbeKey.getEncoded();
            if (pbeKey.shouldTryWrongPKCS12()) {
                key = new byte[2];
            }
            generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());
            CipherParameters param = generator.generateDerivedMacParameters(pbeKey.getKeySize());
            for (int i = 0; i != key.length; i++) {
                key[i] = (byte) 0;
            }
            return param;
        }

        static CipherParameters makePBEParameters(PBEKeySpec keySpec, int type, int hash, int keySize, int ivSize) {
            byte[] key;
            CipherParameters param;
            PBEParametersGenerator generator = makePBEGenerator(type, hash);
            if (type == 2) {
                key = PBEParametersGenerator.PKCS12PasswordToBytes(keySpec.getPassword());
            } else {
                key = PBEParametersGenerator.PKCS5PasswordToBytes(keySpec.getPassword());
            }
            generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());
            if (ivSize != 0) {
                param = generator.generateDerivedParameters(keySize, ivSize);
            } else {
                param = generator.generateDerivedParameters(keySize);
            }
            for (int i = 0; i != key.length; i++) {
                key[i] = (byte) 0;
            }
            return param;
        }

        static CipherParameters makePBEMacParameters(PBEKeySpec keySpec, int type, int hash, int keySize) {
            byte[] key;
            PBEParametersGenerator generator = makePBEGenerator(type, hash);
            if (type == 2) {
                key = PBEParametersGenerator.PKCS12PasswordToBytes(keySpec.getPassword());
            } else {
                key = PBEParametersGenerator.PKCS5PasswordToBytes(keySpec.getPassword());
            }
            generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());
            CipherParameters param = generator.generateDerivedMacParameters(keySize);
            for (int i = 0; i != key.length; i++) {
                key[i] = (byte) 0;
            }
            return param;
        }
    }
}
