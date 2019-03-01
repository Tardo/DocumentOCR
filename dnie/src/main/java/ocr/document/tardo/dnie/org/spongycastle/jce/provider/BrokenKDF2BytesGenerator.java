package org.spongycastle.jce.provider;

import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.DerivationFunction;
import org.spongycastle.crypto.DerivationParameters;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.params.KDFParameters;

public class BrokenKDF2BytesGenerator implements DerivationFunction {
    private Digest digest;
    private byte[] iv;
    private byte[] shared;

    public BrokenKDF2BytesGenerator(Digest digest) {
        this.digest = digest;
    }

    public void init(DerivationParameters param) {
        if (param instanceof KDFParameters) {
            KDFParameters p = (KDFParameters) param;
            this.shared = p.getSharedSecret();
            this.iv = p.getIV();
            return;
        }
        throw new IllegalArgumentException("KDF parameters required for KDF2Generator");
    }

    public Digest getDigest() {
        return this.digest;
    }

    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException, IllegalArgumentException {
        if (out.length - len < outOff) {
            throw new DataLengthException("output buffer too small");
        }
        long oBits = (long) (len * 8);
        if (oBits > ((long) (this.digest.getDigestSize() * 8)) * 29) {
            IllegalArgumentException illegalArgumentException = new IllegalArgumentException("Output length to large");
        }
        int cThreshold = (int) (oBits / ((long) this.digest.getDigestSize()));
        byte[] dig = new byte[this.digest.getDigestSize()];
        for (int counter = 1; counter <= cThreshold; counter++) {
            this.digest.update(this.shared, 0, this.shared.length);
            this.digest.update((byte) (counter & 255));
            this.digest.update((byte) ((counter >> 8) & 255));
            this.digest.update((byte) ((counter >> 16) & 255));
            this.digest.update((byte) ((counter >> 24) & 255));
            this.digest.update(this.iv, 0, this.iv.length);
            this.digest.doFinal(dig, 0);
            if (len - outOff > dig.length) {
                System.arraycopy(dig, 0, out, outOff, dig.length);
                outOff += dig.length;
            } else {
                System.arraycopy(dig, 0, out, outOff, len - outOff);
            }
        }
        this.digest.reset();
        return len;
    }
}
