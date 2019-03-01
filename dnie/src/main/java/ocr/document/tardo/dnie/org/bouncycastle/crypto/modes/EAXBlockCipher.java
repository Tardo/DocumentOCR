package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class EAXBlockCipher implements AEADBlockCipher {
    private static final byte cTAG = (byte) 2;
    private static final byte hTAG = (byte) 1;
    private static final byte nTAG = (byte) 0;
    private byte[] associatedTextMac = new byte[this.mac.getMacSize()];
    private int blockSize;
    private byte[] bufBlock = new byte[(this.blockSize * 2)];
    private int bufOff;
    private SICBlockCipher cipher;
    private boolean cipherInitialized;
    private boolean forEncryption;
    private byte[] initialAssociatedText;
    private Mac mac;
    private byte[] macBlock = new byte[this.blockSize];
    private int macSize;
    private byte[] nonceMac = new byte[this.mac.getMacSize()];

    public EAXBlockCipher(BlockCipher blockCipher) {
        this.blockSize = blockCipher.getBlockSize();
        this.mac = new CMac(blockCipher);
        this.cipher = new SICBlockCipher(blockCipher);
    }

    private void calculateMac() {
        int i = 0;
        byte[] bArr = new byte[this.blockSize];
        this.mac.doFinal(bArr, 0);
        while (i < this.macBlock.length) {
            this.macBlock[i] = (byte) ((this.nonceMac[i] ^ this.associatedTextMac[i]) ^ bArr[i]);
            i++;
        }
    }

    private void initCipher() {
        if (!this.cipherInitialized) {
            this.cipherInitialized = true;
            this.mac.doFinal(this.associatedTextMac, 0);
            byte[] bArr = new byte[this.blockSize];
            bArr[this.blockSize - 1] = (byte) 2;
            this.mac.update(bArr, 0, this.blockSize);
        }
    }

    private int process(byte b, byte[] bArr, int i) {
        byte[] bArr2 = this.bufBlock;
        int i2 = this.bufOff;
        this.bufOff = i2 + 1;
        bArr2[i2] = b;
        if (this.bufOff != this.bufBlock.length) {
            return 0;
        }
        int processBlock;
        if (this.forEncryption) {
            processBlock = this.cipher.processBlock(this.bufBlock, 0, bArr, i);
            this.mac.update(bArr, i, this.blockSize);
        } else {
            this.mac.update(this.bufBlock, 0, this.blockSize);
            processBlock = this.cipher.processBlock(this.bufBlock, 0, bArr, i);
        }
        this.bufOff = this.blockSize;
        System.arraycopy(this.bufBlock, this.blockSize, this.bufBlock, 0, this.blockSize);
        return processBlock;
    }

    private void reset(boolean z) {
        this.cipher.reset();
        this.mac.reset();
        this.bufOff = 0;
        Arrays.fill(this.bufBlock, (byte) 0);
        if (z) {
            Arrays.fill(this.macBlock, (byte) 0);
        }
        byte[] bArr = new byte[this.blockSize];
        bArr[this.blockSize - 1] = (byte) 1;
        this.mac.update(bArr, 0, this.blockSize);
        this.cipherInitialized = false;
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
    }

    private boolean verifyMac(byte[] bArr, int i) {
        int i2 = 0;
        for (int i3 = 0; i3 < this.macSize; i3++) {
            i2 |= this.macBlock[i3] ^ bArr[i + i3];
        }
        return i2 == 0;
    }

    public int doFinal(byte[] bArr, int i) throws IllegalStateException, InvalidCipherTextException {
        initCipher();
        int i2 = this.bufOff;
        Object obj = new byte[this.bufBlock.length];
        this.bufOff = 0;
        if (this.forEncryption) {
            this.cipher.processBlock(this.bufBlock, 0, obj, 0);
            this.cipher.processBlock(this.bufBlock, this.blockSize, obj, this.blockSize);
            System.arraycopy(obj, 0, bArr, i, i2);
            this.mac.update(obj, 0, i2);
            calculateMac();
            System.arraycopy(this.macBlock, 0, bArr, i + i2, this.macSize);
            reset(false);
            return i2 + this.macSize;
        }
        if (i2 > this.macSize) {
            this.mac.update(this.bufBlock, 0, i2 - this.macSize);
            this.cipher.processBlock(this.bufBlock, 0, obj, 0);
            this.cipher.processBlock(this.bufBlock, this.blockSize, obj, this.blockSize);
            System.arraycopy(obj, 0, bArr, i, i2 - this.macSize);
        }
        calculateMac();
        if (verifyMac(this.bufBlock, i2 - this.macSize)) {
            reset(false);
            return i2 - this.macSize;
        }
        throw new InvalidCipherTextException("mac check in EAX failed");
    }

    public String getAlgorithmName() {
        return this.cipher.getUnderlyingCipher().getAlgorithmName() + "/EAX";
    }

    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    public byte[] getMac() {
        Object obj = new byte[this.macSize];
        System.arraycopy(this.macBlock, 0, obj, 0, this.macSize);
        return obj;
    }

    public int getOutputSize(int i) {
        int i2 = this.bufOff + i;
        return this.forEncryption ? i2 + this.macSize : i2 < this.macSize ? 0 : i2 - this.macSize;
    }

    public BlockCipher getUnderlyingCipher() {
        return this.cipher.getUnderlyingCipher();
    }

    public int getUpdateOutputSize(int i) {
        int i2 = this.bufOff + i;
        if (!this.forEncryption) {
            if (i2 < this.macSize) {
                return 0;
            }
            i2 -= this.macSize;
        }
        return i2 - (i2 % this.blockSize);
    }

    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        byte[] nonce;
        CipherParameters key;
        this.forEncryption = z;
        if (cipherParameters instanceof AEADParameters) {
            AEADParameters aEADParameters = (AEADParameters) cipherParameters;
            nonce = aEADParameters.getNonce();
            this.initialAssociatedText = aEADParameters.getAssociatedText();
            this.macSize = aEADParameters.getMacSize() / 8;
            key = aEADParameters.getKey();
        } else if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            nonce = parametersWithIV.getIV();
            this.initialAssociatedText = null;
            this.macSize = this.mac.getMacSize() / 2;
            key = parametersWithIV.getParameters();
        } else {
            throw new IllegalArgumentException("invalid parameters passed to EAX");
        }
        byte[] bArr = new byte[this.blockSize];
        this.mac.init(key);
        bArr[this.blockSize - 1] = (byte) 0;
        this.mac.update(bArr, 0, this.blockSize);
        this.mac.update(nonce, 0, nonce.length);
        this.mac.doFinal(this.nonceMac, 0);
        bArr[this.blockSize - 1] = (byte) 1;
        this.mac.update(bArr, 0, this.blockSize);
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
        this.cipher.init(true, new ParametersWithIV(null, this.nonceMac));
    }

    public void processAADByte(byte b) {
        if (this.cipherInitialized) {
            throw new IllegalStateException("AAD data cannot be added after encryption/decription processing has begun.");
        }
        this.mac.update(b);
    }

    public void processAADBytes(byte[] bArr, int i, int i2) {
        if (this.cipherInitialized) {
            throw new IllegalStateException("AAD data cannot be added after encryption/decription processing has begun.");
        }
        this.mac.update(bArr, i, i2);
    }

    public int processByte(byte b, byte[] bArr, int i) throws DataLengthException {
        initCipher();
        return process(b, bArr, i);
    }

    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        int i4 = 0;
        initCipher();
        int i5 = 0;
        while (i4 != i2) {
            i5 += process(bArr[i + i4], bArr2, i3 + i5);
            i4++;
        }
        return i5;
    }

    public void reset() {
        reset(true);
    }
}
