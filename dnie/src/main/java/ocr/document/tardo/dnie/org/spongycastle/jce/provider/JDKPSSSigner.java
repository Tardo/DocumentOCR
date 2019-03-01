package org.spongycastle.jce.provider;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.engines.RSABlindedEngine;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.PSSSigner;

public class JDKPSSSigner extends SignatureSpi {
    private Digest contentDigest;
    private AlgorithmParameters engineParams;
    private boolean isRaw;
    private Digest mgfDigest;
    private PSSParameterSpec originalSpec;
    private PSSParameterSpec paramSpec;
    private PSSSigner pss;
    private int saltLength;
    private AsymmetricBlockCipher signer;
    private byte trailer;

    private class NullPssDigest implements Digest {
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        private Digest baseDigest;
        private boolean oddTime = true;

        public NullPssDigest(Digest mgfDigest) {
            this.baseDigest = mgfDigest;
        }

        public String getAlgorithmName() {
            return "NULL";
        }

        public int getDigestSize() {
            return this.baseDigest.getDigestSize();
        }

        public void update(byte in) {
            this.bOut.write(in);
        }

        public void update(byte[] in, int inOff, int len) {
            this.bOut.write(in, inOff, len);
        }

        public int doFinal(byte[] out, int outOff) {
            boolean z = false;
            byte[] res = this.bOut.toByteArray();
            if (this.oddTime) {
                System.arraycopy(res, 0, out, outOff, res.length);
            } else {
                this.baseDigest.update(res, 0, res.length);
                this.baseDigest.doFinal(out, outOff);
            }
            reset();
            if (!this.oddTime) {
                z = true;
            }
            this.oddTime = z;
            return res.length;
        }

        public void reset() {
            this.bOut.reset();
            this.baseDigest.reset();
        }
    }

    public static class PSSwithRSA extends JDKPSSSigner {
        public PSSwithRSA() {
            super(new RSABlindedEngine(), null);
        }
    }

    public static class SHA1withRSA extends JDKPSSSigner {
        public SHA1withRSA() {
            super(new RSABlindedEngine(), PSSParameterSpec.DEFAULT);
        }
    }

    public static class SHA224withRSA extends JDKPSSSigner {
        public SHA224withRSA() {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), 28, 1));
        }
    }

    public static class SHA256withRSA extends JDKPSSSigner {
        public SHA256withRSA() {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
        }
    }

    public static class SHA384withRSA extends JDKPSSSigner {
        public SHA384withRSA() {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1));
        }
    }

    public static class SHA512withRSA extends JDKPSSSigner {
        public SHA512withRSA() {
            super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 64, 1));
        }
    }

    public static class nonePSS extends JDKPSSSigner {
        public nonePSS() {
            super(new RSABlindedEngine(), null, true);
        }
    }

    private byte getTrailer(int trailerField) {
        if (trailerField == 1) {
            return (byte) -68;
        }
        throw new IllegalArgumentException("unknown trailer field");
    }

    private void setupContentDigest() {
        if (this.isRaw) {
            this.contentDigest = new NullPssDigest(this.mgfDigest);
        } else {
            this.contentDigest = this.mgfDigest;
        }
    }

    protected JDKPSSSigner(AsymmetricBlockCipher signer, PSSParameterSpec paramSpecArg) {
        this(signer, paramSpecArg, false);
    }

    protected JDKPSSSigner(AsymmetricBlockCipher signer, PSSParameterSpec baseParamSpec, boolean isRaw) {
        this.signer = signer;
        this.originalSpec = baseParamSpec;
        if (baseParamSpec == null) {
            this.paramSpec = PSSParameterSpec.DEFAULT;
        } else {
            this.paramSpec = baseParamSpec;
        }
        this.mgfDigest = JCEDigestUtil.getDigest(this.paramSpec.getDigestAlgorithm());
        this.saltLength = this.paramSpec.getSaltLength();
        this.trailer = getTrailer(this.paramSpec.getTrailerField());
        this.isRaw = isRaw;
        setupContentDigest();
    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey instanceof RSAPublicKey) {
            this.pss = new PSSSigner(this.signer, this.contentDigest, this.mgfDigest, this.saltLength, this.trailer);
            this.pss.init(false, RSAUtil.generatePublicKeyParameter((RSAPublicKey) publicKey));
            return;
        }
        throw new InvalidKeyException("Supplied key is not a RSAPublicKey instance");
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        if (privateKey instanceof RSAPrivateKey) {
            this.pss = new PSSSigner(this.signer, this.contentDigest, this.mgfDigest, this.saltLength, this.trailer);
            this.pss.init(true, new ParametersWithRandom(RSAUtil.generatePrivateKeyParameter((RSAPrivateKey) privateKey), random));
            return;
        }
        throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
    }

    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof RSAPrivateKey) {
            this.pss = new PSSSigner(this.signer, this.contentDigest, this.mgfDigest, this.saltLength, this.trailer);
            this.pss.init(true, RSAUtil.generatePrivateKeyParameter((RSAPrivateKey) privateKey));
            return;
        }
        throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
    }

    protected void engineUpdate(byte b) throws SignatureException {
        this.pss.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.pss.update(b, off, len);
    }

    protected byte[] engineSign() throws SignatureException {
        try {
            return this.pss.generateSignature();
        } catch (CryptoException e) {
            throw new SignatureException(e.getMessage());
        }
    }

    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return this.pss.verifySignature(sigBytes);
    }

    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidParameterException {
        if (params instanceof PSSParameterSpec) {
            PSSParameterSpec newParamSpec = (PSSParameterSpec) params;
            if (this.originalSpec != null && !JCEDigestUtil.isSameDigest(this.originalSpec.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm())) {
                throw new InvalidParameterException("parameter must be using " + this.originalSpec.getDigestAlgorithm());
            } else if (!newParamSpec.getMGFAlgorithm().equalsIgnoreCase("MGF1") && !newParamSpec.getMGFAlgorithm().equals(PKCSObjectIdentifiers.id_mgf1.getId())) {
                throw new InvalidParameterException("unknown mask generation function specified");
            } else if (newParamSpec.getMGFParameters() instanceof MGF1ParameterSpec) {
                MGF1ParameterSpec mgfParams = (MGF1ParameterSpec) newParamSpec.getMGFParameters();
                if (JCEDigestUtil.isSameDigest(mgfParams.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm())) {
                    Digest newDigest = JCEDigestUtil.getDigest(mgfParams.getDigestAlgorithm());
                    if (newDigest == null) {
                        throw new InvalidParameterException("no match on MGF digest algorithm: " + mgfParams.getDigestAlgorithm());
                    }
                    this.engineParams = null;
                    this.paramSpec = newParamSpec;
                    this.mgfDigest = newDigest;
                    this.saltLength = this.paramSpec.getSaltLength();
                    this.trailer = getTrailer(this.paramSpec.getTrailerField());
                    setupContentDigest();
                    return;
                }
                throw new InvalidParameterException("digest algorithm for MGF should be the same as for PSS parameters.");
            } else {
                throw new InvalidParameterException("unkown MGF parameters");
            }
        }
        throw new InvalidParameterException("Only PSSParameterSpec supported");
    }

    protected AlgorithmParameters engineGetParameters() {
        if (this.engineParams == null && this.paramSpec != null) {
            try {
                this.engineParams = AlgorithmParameters.getInstance("PSS", BouncyCastleProvider.PROVIDER_NAME);
                this.engineParams.init(this.paramSpec);
            } catch (Exception e) {
                throw new RuntimeException(e.toString());
            }
        }
        return this.engineParams;
    }

    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }
}
