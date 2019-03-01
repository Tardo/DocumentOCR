package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSADigestSigner;

public abstract class TlsDSASigner extends AbstractTlsSigner {
    protected abstract DSA createDSAImpl();

    public Signer createSigner(AsymmetricKeyParameter asymmetricKeyParameter) {
        return makeSigner(new SHA1Digest(), true, new ParametersWithRandom(asymmetricKeyParameter, this.context.getSecureRandom()));
    }

    public Signer createVerifyer(AsymmetricKeyParameter asymmetricKeyParameter) {
        return makeSigner(new SHA1Digest(), false, asymmetricKeyParameter);
    }

    public byte[] generateRawSignature(AsymmetricKeyParameter asymmetricKeyParameter, byte[] bArr) throws CryptoException {
        Signer makeSigner = makeSigner(new NullDigest(), true, new ParametersWithRandom(asymmetricKeyParameter, this.context.getSecureRandom()));
        makeSigner.update(bArr, 16, 20);
        return makeSigner.generateSignature();
    }

    protected Signer makeSigner(Digest digest, boolean z, CipherParameters cipherParameters) {
        Signer dSADigestSigner = new DSADigestSigner(createDSAImpl(), digest);
        dSADigestSigner.init(z, cipherParameters);
        return dSADigestSigner;
    }

    public boolean verifyRawSignature(byte[] bArr, AsymmetricKeyParameter asymmetricKeyParameter, byte[] bArr2) throws CryptoException {
        Signer makeSigner = makeSigner(new NullDigest(), false, asymmetricKeyParameter);
        makeSigner.update(bArr2, 16, 20);
        return makeSigner.verifySignature(bArr);
    }
}
