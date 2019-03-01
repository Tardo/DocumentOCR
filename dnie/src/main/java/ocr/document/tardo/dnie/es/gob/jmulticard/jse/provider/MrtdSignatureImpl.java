package es.gob.jmulticard.jse.provider;

import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.dnie.mrtd.DnieMrtd;
import es.gob.jmulticard.card.dnie.mrtd.DnieMrtdPrivateKeyReference;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;

abstract class MrtdSignatureImpl extends SignatureSpi {
    private final ByteArrayOutputStream data = new ByteArrayOutputStream();
    private MrtdPrivateKey privateKey = null;
    private final String signatureAlgo;
    private Signature signatureVerifier = null;

    public static final class None extends MrtdSignatureImpl {
        public None() {
            super("NONEwithRSA");
        }
    }

    public static final class Sha1 extends MrtdSignatureImpl {
        public Sha1() {
            super(DnieProvider.SHA1WITH_RSA);
        }
    }

    public static final class Sha256 extends MrtdSignatureImpl {
        public Sha256() {
            super("SHA256withRSA");
        }
    }

    public static final class Sha384 extends MrtdSignatureImpl {
        public Sha384() {
            super("SHA384withRSA");
        }
    }

    public static final class Sha512 extends MrtdSignatureImpl {
        public Sha512() {
            super("SHA512withRSA");
        }
    }

    MrtdSignatureImpl(String signatureAlgorithm) {
        this.signatureAlgo = signatureAlgorithm;
    }

    protected Object engineGetParameter(String param) {
        throw new InvalidParameterException("Parametro no soportado");
    }

    protected void engineInitSign(PrivateKey prKey) throws InvalidKeyException {
        if (prKey == null) {
            throw new InvalidKeyException("La clave proporcionada es nula");
        } else if (prKey instanceof MrtdPrivateKey) {
            this.privateKey = (MrtdPrivateKey) prKey;
            this.data.reset();
        } else {
            throw new InvalidKeyException("La clave proporcionada no es de un DNIeMrtd: " + prKey.getClass().getName());
        }
    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        this.data.reset();
        try {
            this.signatureVerifier = Signature.getInstance(this.signatureAlgo);
            if (this.signatureVerifier.getProvider() instanceof DnieProvider) {
                this.signatureVerifier = Signature.getInstance(this.signatureAlgo, "SunRsaSign");
            }
            this.signatureVerifier.initVerify(publicKey);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("No esta instalado el proveedor SunRsaSign", e);
        } catch (NoSuchAlgorithmException e2) {
            throw new IllegalStateException("No existe un proveedor para validar firmas con el algoritmo " + this.signatureAlgo, e2);
        }
    }

    protected void engineSetParameter(String param, Object value) {
        throw new InvalidParameterException("Parametro no soportado");
    }

    protected byte[] engineSign() throws SignatureException {
        if (this.privateKey.getCryptoCard() instanceof DnieMrtd) {
            try {
                return this.privateKey.getCryptoCard().sign(this.data.toByteArray(), this.signatureAlgo, new DnieMrtdPrivateKeyReference((DnieMrtd) this.privateKey.getCryptoCard(), this.privateKey.getId(), this.privateKey.getPath(), this.privateKey.toString()));
            } catch (CryptoCardException e) {
                throw new SignatureException(e);
            }
        }
        throw new ProviderException("La clave proporcionada no se corresponde con la de un DNIe");
    }

    protected void engineUpdate(byte b) throws SignatureException {
        this.data.write(b);
    }

    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.data.write(b, off, len);
    }

    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (this.signatureVerifier == null) {
            throw new SignatureException("La verificacion no esta inicializada");
        }
        this.signatureVerifier.update(this.data.toByteArray());
        this.data.reset();
        return this.signatureVerifier.verify(sigBytes);
    }
}
