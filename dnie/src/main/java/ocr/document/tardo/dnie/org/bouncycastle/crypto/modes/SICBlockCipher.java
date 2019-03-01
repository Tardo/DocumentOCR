package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class SICBlockCipher implements BlockCipher {
    private byte[] IV = new byte[this.blockSize];
    private final int blockSize = this.cipher.getBlockSize();
    private final BlockCipher cipher;
    private byte[] counter = new byte[this.blockSize];
    private byte[] counterOut = new byte[this.blockSize];

    public SICBlockCipher(BlockCipher blockCipher) {
        this.cipher = blockCipher;
    }

    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/SIC";
    }

    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    public BlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            System.arraycopy(parametersWithIV.getIV(), 0, this.IV, 0, this.IV.length);
            reset();
            if (parametersWithIV.getParameters() != null) {
                this.cipher.init(true, parametersWithIV.getParameters());
                return;
            }
            return;
        }
        throw new IllegalArgumentException("SIC mode requires ParametersWithIV");
    }

    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        int i3 = 0;
        this.cipher.processBlock(this.counter, 0, this.counterOut, 0);
        while (i3 < this.counterOut.length) {
            bArr2[i2 + i3] = (byte) (this.counterOut[i3] ^ bArr[i + i3]);
            i3++;
        }
        for (i3 = this.counter.length - 1; i3 >= 0; i3--) {
            byte[] bArr3 = this.counter;
            byte b = (byte) (bArr3[i3] + 1);
            bArr3[i3] = b;
            if (b != (byte) 0) {
                break;
            }
        }
        return this.counter.length;
    }

    public void reset() {
        System.arraycopy(this.IV, 0, this.counter, 0, this.counter.length);
        this.cipher.reset();
    }
}
