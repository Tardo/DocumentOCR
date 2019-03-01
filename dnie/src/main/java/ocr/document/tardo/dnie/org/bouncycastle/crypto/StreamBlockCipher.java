package org.bouncycastle.crypto;

public class StreamBlockCipher implements StreamCipher {
    private BlockCipher cipher;
    private byte[] oneByte = new byte[1];

    public StreamBlockCipher(BlockCipher blockCipher) {
        if (blockCipher.getBlockSize() != 1) {
            throw new IllegalArgumentException("block cipher block size != 1.");
        }
        this.cipher = blockCipher;
    }

    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName();
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        this.cipher.init(z, cipherParameters);
    }

    public void processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        if (i3 + i2 > bArr2.length) {
            throw new DataLengthException("output buffer too small in processBytes()");
        }
        for (int i4 = 0; i4 != i2; i4++) {
            this.cipher.processBlock(bArr, i + i4, bArr2, i3 + i4);
        }
    }

    public void reset() {
        this.cipher.reset();
    }

    public byte returnByte(byte b) {
        this.oneByte[0] = b;
        this.cipher.processBlock(this.oneByte, 0, this.oneByte, 0);
        return this.oneByte[0];
    }
}
