package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.GenericSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.Arrays;

public class TlsRSASigner extends AbstractTlsSigner {
    protected AsymmetricBlockCipher createRSAImpl() {
        return new PKCS1Encoding(new RSABlindedEngine());
    }

    public Signer createSigner(AsymmetricKeyParameter asymmetricKeyParameter) {
        return makeSigner(new CombinedHash(), true, new ParametersWithRandom(asymmetricKeyParameter, this.context.getSecureRandom()));
    }

    public Signer createVerifyer(AsymmetricKeyParameter asymmetricKeyParameter) {
        return makeSigner(new CombinedHash(), false, asymmetricKeyParameter);
    }

    public byte[] generateRawSignature(AsymmetricKeyParameter asymmetricKeyParameter, byte[] bArr) throws CryptoException {
        AsymmetricBlockCipher createRSAImpl = createRSAImpl();
        createRSAImpl.init(true, new ParametersWithRandom(asymmetricKeyParameter, this.context.getSecureRandom()));
        return createRSAImpl.processBlock(bArr, 0, bArr.length);
    }

    public boolean isValidPublicKey(AsymmetricKeyParameter asymmetricKeyParameter) {
        return (asymmetricKeyParameter instanceof RSAKeyParameters) && !asymmetricKeyParameter.isPrivate();
    }

    protected Signer makeSigner(Digest digest, boolean z, CipherParameters cipherParameters) {
        Signer rSADigestSigner = ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(this.context.getServerVersion().getEquivalentTLSVersion()) ? new RSADigestSigner(digest) : new GenericSigner(createRSAImpl(), digest);
        rSADigestSigner.init(z, cipherParameters);
        return rSADigestSigner;
    }

    public boolean verifyRawSignature(byte[] bArr, AsymmetricKeyParameter asymmetricKeyParameter, byte[] bArr2) throws CryptoException {
        AsymmetricBlockCipher createRSAImpl = createRSAImpl();
        createRSAImpl.init(false, asymmetricKeyParameter);
        return Arrays.constantTimeAreEqual(createRSAImpl.processBlock(bArr, 0, bArr.length), bArr2);
    }
}
