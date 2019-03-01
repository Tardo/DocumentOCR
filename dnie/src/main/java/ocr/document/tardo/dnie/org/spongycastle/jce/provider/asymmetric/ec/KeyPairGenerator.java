package org.spongycastle.jce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Hashtable;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.spongycastle.asn1.nist.NISTNamedCurves;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.spongycastle.asn1.x9.X962NamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jce.provider.JCEECPrivateKey;
import org.spongycastle.jce.provider.JCEECPublicKey;
import org.spongycastle.jce.provider.JDKKeyPairGenerator;
import org.spongycastle.jce.provider.ProviderUtil;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.jce.spec.ECParameterSpec;

public abstract class KeyPairGenerator extends JDKKeyPairGenerator {

    public static class EC extends KeyPairGenerator {
        private static Hashtable ecParameters = new Hashtable();
        String algorithm;
        int certainty;
        Object ecParams;
        ECKeyPairGenerator engine;
        boolean initialised;
        ECKeyGenerationParameters param;
        SecureRandom random;
        int strength;

        static {
            ecParameters.put(new Integer(192), new ECGenParameterSpec("prime192v1"));
            ecParameters.put(new Integer(239), new ECGenParameterSpec("prime239v1"));
            ecParameters.put(new Integer(256), new ECGenParameterSpec("prime256v1"));
            ecParameters.put(new Integer(224), new ECGenParameterSpec("P-224"));
            ecParameters.put(new Integer(384), new ECGenParameterSpec("P-384"));
            ecParameters.put(new Integer(521), new ECGenParameterSpec("P-521"));
        }

        public EC() {
            super("EC");
            this.engine = new ECKeyPairGenerator();
            this.ecParams = null;
            this.strength = 239;
            this.certainty = 50;
            this.random = new SecureRandom();
            this.initialised = false;
            this.algorithm = "EC";
        }

        public EC(String algorithm) {
            super(algorithm);
            this.engine = new ECKeyPairGenerator();
            this.ecParams = null;
            this.strength = 239;
            this.certainty = 50;
            this.random = new SecureRandom();
            this.initialised = false;
            this.algorithm = algorithm;
        }

        public void initialize(int strength, SecureRandom random) {
            this.strength = strength;
            this.random = random;
            this.ecParams = ecParameters.get(new Integer(strength));
            if (this.ecParams != null) {
                try {
                    initialize((ECGenParameterSpec) this.ecParams, random);
                    return;
                } catch (InvalidAlgorithmParameterException e) {
                    throw new InvalidParameterException("key size not configurable.");
                }
            }
            throw new InvalidParameterException("unknown key size.");
        }

        public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
            ECParameterSpec p;
            if (params instanceof ECParameterSpec) {
                p = (ECParameterSpec) params;
                this.ecParams = params;
                this.param = new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN()), random);
                this.engine.init(this.param);
                this.initialised = true;
            } else if (params instanceof java.security.spec.ECParameterSpec) {
                p = (java.security.spec.ECParameterSpec) params;
                this.ecParams = params;
                curve = EC5Util.convertCurve(p.getCurve());
                this.param = new ECKeyGenerationParameters(new ECDomainParameters(curve, EC5Util.convertPoint(curve, p.getGenerator(), false), p.getOrder(), BigInteger.valueOf((long) p.getCofactor())), random);
                this.engine.init(this.param);
                this.initialised = true;
            } else if (params instanceof ECGenParameterSpec) {
                String curveName = ((ECGenParameterSpec) params).getName();
                if (this.algorithm.equals("ECGOST3410")) {
                    ECDomainParameters ecP = ECGOST3410NamedCurves.getByName(curveName);
                    if (ecP == null) {
                        throw new InvalidAlgorithmParameterException("unknown curve name: " + curveName);
                    }
                    this.ecParams = new ECNamedCurveSpec(curveName, ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
                } else {
                    X9ECParameters ecP2 = X962NamedCurves.getByName(curveName);
                    if (ecP2 == null) {
                        ecP2 = SECNamedCurves.getByName(curveName);
                        if (ecP2 == null) {
                            ecP2 = NISTNamedCurves.getByName(curveName);
                        }
                        if (ecP2 == null) {
                            ecP2 = TeleTrusTNamedCurves.getByName(curveName);
                        }
                        if (ecP2 == null) {
                            try {
                                DERObjectIdentifier oid = new DERObjectIdentifier(curveName);
                                ecP2 = X962NamedCurves.getByOID(oid);
                                if (ecP2 == null) {
                                    ecP2 = SECNamedCurves.getByOID(oid);
                                }
                                if (ecP2 == null) {
                                    ecP2 = NISTNamedCurves.getByOID(oid);
                                }
                                if (ecP2 == null) {
                                    ecP2 = TeleTrusTNamedCurves.getByOID(oid);
                                }
                                if (ecP2 == null) {
                                    throw new InvalidAlgorithmParameterException("unknown curve OID: " + curveName);
                                }
                            } catch (IllegalArgumentException e) {
                                throw new InvalidAlgorithmParameterException("unknown curve name: " + curveName);
                            }
                        }
                    }
                    this.ecParams = new ECNamedCurveSpec(curveName, ecP2.getCurve(), ecP2.getG(), ecP2.getN(), ecP2.getH(), null);
                }
                p = (java.security.spec.ECParameterSpec) this.ecParams;
                curve = EC5Util.convertCurve(p.getCurve());
                this.param = new ECKeyGenerationParameters(new ECDomainParameters(curve, EC5Util.convertPoint(curve, p.getGenerator(), false), p.getOrder(), BigInteger.valueOf((long) p.getCofactor())), random);
                this.engine.init(this.param);
                this.initialised = true;
            } else if (params == null && ProviderUtil.getEcImplicitlyCa() != null) {
                p = ProviderUtil.getEcImplicitlyCa();
                this.ecParams = params;
                this.param = new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN()), random);
                this.engine.init(this.param);
                this.initialised = true;
            } else if (params == null && ProviderUtil.getEcImplicitlyCa() == null) {
                throw new InvalidAlgorithmParameterException("null parameter passed but no implicitCA set");
            } else {
                throw new InvalidAlgorithmParameterException("parameter object not a ECParameterSpec");
            }
        }

        public KeyPair generateKeyPair() {
            if (this.initialised) {
                AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
                ECPublicKeyParameters pub = (ECPublicKeyParameters) pair.getPublic();
                ECPrivateKeyParameters priv = (ECPrivateKeyParameters) pair.getPrivate();
                JCEECPublicKey pubKey;
                if (this.ecParams instanceof ECParameterSpec) {
                    ECParameterSpec p = this.ecParams;
                    pubKey = new JCEECPublicKey(this.algorithm, pub, p);
                    return new KeyPair(pubKey, new JCEECPrivateKey(this.algorithm, priv, pubKey, p));
                } else if (this.ecParams == null) {
                    return new KeyPair(new JCEECPublicKey(this.algorithm, pub), new JCEECPrivateKey(this.algorithm, priv));
                } else {
                    java.security.spec.ECParameterSpec p2 = this.ecParams;
                    pubKey = new JCEECPublicKey(this.algorithm, pub, p2);
                    return new KeyPair(pubKey, new JCEECPrivateKey(this.algorithm, priv, pubKey, p2));
                }
            }
            throw new IllegalStateException("EC Key Pair Generator not initialised");
        }
    }

    public static class ECDH extends EC {
        public ECDH() {
            super("ECDH");
        }
    }

    public static class ECDHC extends EC {
        public ECDHC() {
            super("ECDHC");
        }
    }

    public static class ECDSA extends EC {
        public ECDSA() {
            super("ECDSA");
        }
    }

    public static class ECGOST3410 extends EC {
        public ECGOST3410() {
            super("ECGOST3410");
        }
    }

    public static class ECMQV extends EC {
        public ECMQV() {
            super("ECMQV");
        }
    }

    public KeyPairGenerator(String algorithmName) {
        super(algorithmName);
    }
}
