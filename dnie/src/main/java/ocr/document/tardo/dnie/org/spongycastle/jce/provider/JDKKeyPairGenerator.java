package org.spongycastle.jce.provider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Hashtable;
import javax.crypto.spec.DHParameterSpec;
import org.spongycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.spongycastle.crypto.generators.DHParametersGenerator;
import org.spongycastle.crypto.generators.DSAKeyPairGenerator;
import org.spongycastle.crypto.generators.DSAParametersGenerator;
import org.spongycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.spongycastle.crypto.generators.ElGamalParametersGenerator;
import org.spongycastle.crypto.generators.GOST3410KeyPairGenerator;
import org.spongycastle.crypto.generators.RSAKeyPairGenerator;
import org.spongycastle.crypto.params.DHKeyGenerationParameters;
import org.spongycastle.crypto.params.DHParameters;
import org.spongycastle.crypto.params.DHPrivateKeyParameters;
import org.spongycastle.crypto.params.DHPublicKeyParameters;
import org.spongycastle.crypto.params.DSAKeyGenerationParameters;
import org.spongycastle.crypto.params.DSAParameters;
import org.spongycastle.crypto.params.DSAPrivateKeyParameters;
import org.spongycastle.crypto.params.DSAPublicKeyParameters;
import org.spongycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.spongycastle.crypto.params.ElGamalParameters;
import org.spongycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.spongycastle.crypto.params.ElGamalPublicKeyParameters;
import org.spongycastle.crypto.params.GOST3410KeyGenerationParameters;
import org.spongycastle.crypto.params.GOST3410Parameters;
import org.spongycastle.crypto.params.GOST3410PrivateKeyParameters;
import org.spongycastle.crypto.params.GOST3410PublicKeyParameters;
import org.spongycastle.crypto.params.RSAKeyGenerationParameters;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.spongycastle.jce.spec.ElGamalParameterSpec;
import org.spongycastle.jce.spec.GOST3410ParameterSpec;
import org.spongycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

public abstract class JDKKeyPairGenerator extends KeyPairGenerator {

    public static class DH extends JDKKeyPairGenerator {
        private static Hashtable params = new Hashtable();
        int certainty = 20;
        DHBasicKeyPairGenerator engine = new DHBasicKeyPairGenerator();
        boolean initialised = false;
        DHKeyGenerationParameters param;
        SecureRandom random = new SecureRandom();
        int strength = 1024;

        public DH() {
            super("DH");
        }

        public void initialize(int strength, SecureRandom random) {
            this.strength = strength;
            this.random = random;
        }

        public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (params instanceof DHParameterSpec) {
                DHParameterSpec dhParams = (DHParameterSpec) params;
                this.param = new DHKeyGenerationParameters(random, new DHParameters(dhParams.getP(), dhParams.getG(), null, dhParams.getL()));
                this.engine.init(this.param);
                this.initialised = true;
                return;
            }
            throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec");
        }

        public KeyPair generateKeyPair() {
            if (!this.initialised) {
                Integer paramStrength = new Integer(this.strength);
                if (params.containsKey(paramStrength)) {
                    this.param = (DHKeyGenerationParameters) params.get(paramStrength);
                } else {
                    DHParametersGenerator pGen = new DHParametersGenerator();
                    pGen.init(this.strength, this.certainty, this.random);
                    this.param = new DHKeyGenerationParameters(this.random, pGen.generateParameters());
                    params.put(paramStrength, this.param);
                }
                this.engine.init(this.param);
                this.initialised = true;
            }
            AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
            return new KeyPair(new JCEDHPublicKey((DHPublicKeyParameters) pair.getPublic()), new JCEDHPrivateKey((DHPrivateKeyParameters) pair.getPrivate()));
        }
    }

    public static class DSA extends JDKKeyPairGenerator {
        int certainty = 20;
        DSAKeyPairGenerator engine = new DSAKeyPairGenerator();
        boolean initialised = false;
        DSAKeyGenerationParameters param;
        SecureRandom random = new SecureRandom();
        int strength = 1024;

        public DSA() {
            super("DSA");
        }

        public void initialize(int strength, SecureRandom random) {
            if (strength < 512 || strength > 1024 || strength % 64 != 0) {
                throw new InvalidParameterException("strength must be from 512 - 1024 and a multiple of 64");
            }
            this.strength = strength;
            this.random = random;
        }

        public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (params instanceof DSAParameterSpec) {
                DSAParameterSpec dsaParams = (DSAParameterSpec) params;
                this.param = new DSAKeyGenerationParameters(random, new DSAParameters(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG()));
                this.engine.init(this.param);
                this.initialised = true;
                return;
            }
            throw new InvalidAlgorithmParameterException("parameter object not a DSAParameterSpec");
        }

        public KeyPair generateKeyPair() {
            if (!this.initialised) {
                DSAParametersGenerator pGen = new DSAParametersGenerator();
                pGen.init(this.strength, this.certainty, this.random);
                this.param = new DSAKeyGenerationParameters(this.random, pGen.generateParameters());
                this.engine.init(this.param);
                this.initialised = true;
            }
            AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
            return new KeyPair(new JDKDSAPublicKey((DSAPublicKeyParameters) pair.getPublic()), new JDKDSAPrivateKey((DSAPrivateKeyParameters) pair.getPrivate()));
        }
    }

    public static class ElGamal extends JDKKeyPairGenerator {
        int certainty = 20;
        ElGamalKeyPairGenerator engine = new ElGamalKeyPairGenerator();
        boolean initialised = false;
        ElGamalKeyGenerationParameters param;
        SecureRandom random = new SecureRandom();
        int strength = 1024;

        public ElGamal() {
            super("ElGamal");
        }

        public void initialize(int strength, SecureRandom random) {
            this.strength = strength;
            this.random = random;
        }

        public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
            if ((params instanceof ElGamalParameterSpec) || (params instanceof DHParameterSpec)) {
                if (params instanceof ElGamalParameterSpec) {
                    ElGamalParameterSpec elParams = (ElGamalParameterSpec) params;
                    this.param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(elParams.getP(), elParams.getG()));
                } else {
                    DHParameterSpec dhParams = (DHParameterSpec) params;
                    this.param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(dhParams.getP(), dhParams.getG(), dhParams.getL()));
                }
                this.engine.init(this.param);
                this.initialised = true;
                return;
            }
            throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec or an ElGamalParameterSpec");
        }

        public KeyPair generateKeyPair() {
            if (!this.initialised) {
                ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();
                pGen.init(this.strength, this.certainty, this.random);
                this.param = new ElGamalKeyGenerationParameters(this.random, pGen.generateParameters());
                this.engine.init(this.param);
                this.initialised = true;
            }
            AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
            return new KeyPair(new JCEElGamalPublicKey((ElGamalPublicKeyParameters) pair.getPublic()), new JCEElGamalPrivateKey((ElGamalPrivateKeyParameters) pair.getPrivate()));
        }
    }

    public static class GOST3410 extends JDKKeyPairGenerator {
        GOST3410KeyPairGenerator engine = new GOST3410KeyPairGenerator();
        GOST3410ParameterSpec gost3410Params;
        boolean initialised = false;
        GOST3410KeyGenerationParameters param;
        SecureRandom random = null;
        int strength = 1024;

        public GOST3410() {
            super("GOST3410");
        }

        public void initialize(int strength, SecureRandom random) {
            this.strength = strength;
            this.random = random;
        }

        private void init(GOST3410ParameterSpec gParams, SecureRandom random) {
            GOST3410PublicKeyParameterSetSpec spec = gParams.getPublicKeyParameters();
            this.param = new GOST3410KeyGenerationParameters(random, new GOST3410Parameters(spec.getP(), spec.getQ(), spec.getA()));
            this.engine.init(this.param);
            this.initialised = true;
            this.gost3410Params = gParams;
        }

        public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (params instanceof GOST3410ParameterSpec) {
                init((GOST3410ParameterSpec) params, random);
                return;
            }
            throw new InvalidAlgorithmParameterException("parameter object not a GOST3410ParameterSpec");
        }

        public KeyPair generateKeyPair() {
            if (!this.initialised) {
                init(new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_A.getId()), new SecureRandom());
            }
            AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
            return new KeyPair(new JDKGOST3410PublicKey((GOST3410PublicKeyParameters) pair.getPublic(), this.gost3410Params), new JDKGOST3410PrivateKey((GOST3410PrivateKeyParameters) pair.getPrivate(), this.gost3410Params));
        }
    }

    public static class RSA extends JDKKeyPairGenerator {
        static final BigInteger defaultPublicExponent = BigInteger.valueOf(65537);
        static final int defaultTests = 12;
        RSAKeyPairGenerator engine = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters param = new RSAKeyGenerationParameters(defaultPublicExponent, new SecureRandom(), 2048, 12);

        public RSA() {
            super("RSA");
            this.engine.init(this.param);
        }

        public void initialize(int strength, SecureRandom random) {
            this.param = new RSAKeyGenerationParameters(defaultPublicExponent, random, strength, 12);
            this.engine.init(this.param);
        }

        public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (params instanceof RSAKeyGenParameterSpec) {
                RSAKeyGenParameterSpec rsaParams = (RSAKeyGenParameterSpec) params;
                this.param = new RSAKeyGenerationParameters(rsaParams.getPublicExponent(), random, rsaParams.getKeysize(), 12);
                this.engine.init(this.param);
                return;
            }
            throw new InvalidAlgorithmParameterException("parameter object not a RSAKeyGenParameterSpec");
        }

        public KeyPair generateKeyPair() {
            AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
            return new KeyPair(new JCERSAPublicKey((RSAKeyParameters) pair.getPublic()), new JCERSAPrivateCrtKey((RSAPrivateCrtKeyParameters) pair.getPrivate()));
        }
    }

    public abstract KeyPair generateKeyPair();

    public abstract void initialize(int i, SecureRandom secureRandom);

    public JDKKeyPairGenerator(String algorithmName) {
        super(algorithmName);
    }
}
