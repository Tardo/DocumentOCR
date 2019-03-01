package org.spongycastle.jce.provider;

import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import org.spongycastle.crypto.generators.DHParametersGenerator;
import org.spongycastle.crypto.generators.DSAParametersGenerator;
import org.spongycastle.crypto.generators.ElGamalParametersGenerator;
import org.spongycastle.crypto.generators.GOST3410ParametersGenerator;
import org.spongycastle.crypto.params.DHParameters;
import org.spongycastle.crypto.params.DSAParameters;
import org.spongycastle.crypto.params.ElGamalParameters;
import org.spongycastle.crypto.params.GOST3410Parameters;
import org.spongycastle.jce.spec.GOST3410ParameterSpec;
import org.spongycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

public abstract class JDKAlgorithmParameterGenerator extends AlgorithmParameterGeneratorSpi {
    protected SecureRandom random;
    protected int strength = 1024;

    public static class DES extends JDKAlgorithmParameterGenerator {
        protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DES parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters() {
            byte[] iv = new byte[8];
            if (this.random == null) {
                this.random = new SecureRandom();
            }
            this.random.nextBytes(iv);
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("DES", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new IvParameterSpec(iv));
                return params;
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    public static class DH extends JDKAlgorithmParameterGenerator {
        /* renamed from: l */
        private int f419l = 0;

        protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (genParamSpec instanceof DHGenParameterSpec) {
                DHGenParameterSpec spec = (DHGenParameterSpec) genParamSpec;
                this.strength = spec.getPrimeSize();
                this.f419l = spec.getExponentSize();
                this.random = random;
                return;
            }
            throw new InvalidAlgorithmParameterException("DH parameter generator requires a DHGenParameterSpec for initialisation");
        }

        protected AlgorithmParameters engineGenerateParameters() {
            DHParametersGenerator pGen = new DHParametersGenerator();
            if (this.random != null) {
                pGen.init(this.strength, 20, this.random);
            } else {
                pGen.init(this.strength, 20, new SecureRandom());
            }
            DHParameters p = pGen.generateParameters();
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new DHParameterSpec(p.getP(), p.getG(), this.f419l));
                return params;
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    public static class DSA extends JDKAlgorithmParameterGenerator {
        protected void engineInit(int strength, SecureRandom random) {
            if (strength < 512 || strength > 1024 || strength % 64 != 0) {
                throw new InvalidParameterException("strength must be from 512 - 1024 and a multiple of 64");
            }
            this.strength = strength;
            this.random = random;
        }

        protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DSA parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters() {
            DSAParametersGenerator pGen = new DSAParametersGenerator();
            if (this.random != null) {
                pGen.init(this.strength, 20, this.random);
            } else {
                pGen.init(this.strength, 20, new SecureRandom());
            }
            DSAParameters p = pGen.generateParameters();
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new DSAParameterSpec(p.getP(), p.getQ(), p.getG()));
                return params;
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    public static class ElGamal extends JDKAlgorithmParameterGenerator {
        /* renamed from: l */
        private int f420l = 0;

        protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (genParamSpec instanceof DHGenParameterSpec) {
                DHGenParameterSpec spec = (DHGenParameterSpec) genParamSpec;
                this.strength = spec.getPrimeSize();
                this.f420l = spec.getExponentSize();
                this.random = random;
                return;
            }
            throw new InvalidAlgorithmParameterException("DH parameter generator requires a DHGenParameterSpec for initialisation");
        }

        protected AlgorithmParameters engineGenerateParameters() {
            ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();
            if (this.random != null) {
                pGen.init(this.strength, 20, this.random);
            } else {
                pGen.init(this.strength, 20, new SecureRandom());
            }
            ElGamalParameters p = pGen.generateParameters();
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("ElGamal", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new DHParameterSpec(p.getP(), p.getG(), this.f420l));
                return params;
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    public static class GOST3410 extends JDKAlgorithmParameterGenerator {
        protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for GOST3410 parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters() {
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();
            if (this.random != null) {
                pGen.init(this.strength, 2, this.random);
            } else {
                pGen.init(this.strength, 2, new SecureRandom());
            }
            GOST3410Parameters p = pGen.generateParameters();
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("GOST3410", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec(p.getP(), p.getQ(), p.getA())));
                return params;
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    public static class RC2 extends JDKAlgorithmParameterGenerator {
        RC2ParameterSpec spec = null;

        protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (genParamSpec instanceof RC2ParameterSpec) {
                this.spec = (RC2ParameterSpec) genParamSpec;
                return;
            }
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for RC2 parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters() {
            if (this.spec == null) {
                byte[] iv = new byte[8];
                if (this.random == null) {
                    this.random = new SecureRandom();
                }
                this.random.nextBytes(iv);
                try {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("RC2", BouncyCastleProvider.PROVIDER_NAME);
                    params.init(new IvParameterSpec(iv));
                    return params;
                } catch (Exception e) {
                    throw new RuntimeException(e.getMessage());
                }
            }
            try {
                params = AlgorithmParameters.getInstance("RC2", BouncyCastleProvider.PROVIDER_NAME);
                params.init(this.spec);
                return params;
            } catch (Exception e2) {
                throw new RuntimeException(e2.getMessage());
            }
        }
    }

    protected void engineInit(int strength, SecureRandom random) {
        this.strength = strength;
        this.random = random;
    }
}
