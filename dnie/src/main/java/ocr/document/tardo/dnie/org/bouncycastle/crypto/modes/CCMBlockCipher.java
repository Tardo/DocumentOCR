package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class CCMBlockCipher implements AEADBlockCipher {
    private ByteArrayOutputStream associatedText = new ByteArrayOutputStream();
    private int blockSize;
    private BlockCipher cipher;
    private ByteArrayOutputStream data = new ByteArrayOutputStream();
    private boolean forEncryption;
    private byte[] initialAssociatedText;
    private CipherParameters keyParam;
    private byte[] macBlock;
    private int macSize;
    private byte[] nonce;

    public CCMBlockCipher(BlockCipher blockCipher) {
        this.cipher = blockCipher;
        this.blockSize = blockCipher.getBlockSize();
        this.macBlock = new byte[this.blockSize];
        if (this.blockSize != 16) {
            throw new IllegalArgumentException("cipher required with a block size of 16.");
        }
    }

    private int calculateMac(byte[] bArr, int i, int i2, byte[] bArr2) {
        int i3 = 1;
        Mac cBCBlockCipherMac = new CBCBlockCipherMac(this.cipher, this.macSize * 8);
        cBCBlockCipherMac.init(this.keyParam);
        Object obj = new byte[16];
        if (hasAssociatedText()) {
            obj[0] = (byte) (obj[0] | 64);
        }
        obj[0] = (byte) (obj[0] | ((((cBCBlockCipherMac.getMacSize() - 2) / 2) & 7) << 3));
        obj[0] = (byte) (obj[0] | (((15 - this.nonce.length) - 1) & 7));
        System.arraycopy(this.nonce, 0, obj, 1, this.nonce.length);
        int i4 = i2;
        while (i4 > 0) {
            obj[obj.length - i3] = (byte) (i4 & 255);
            i4 >>>= 8;
            i3++;
        }
        cBCBlockCipherMac.update(obj, 0, obj.length);
        if (hasAssociatedText()) {
            i4 = getAssociatedTextLength();
            if (i4 < 65280) {
                cBCBlockCipherMac.update((byte) (i4 >> 8));
                cBCBlockCipherMac.update((byte) i4);
                i3 = 2;
            } else {
                cBCBlockCipherMac.update((byte) -1);
                cBCBlockCipherMac.update((byte) -2);
                cBCBlockCipherMac.update((byte) (i4 >> 24));
                cBCBlockCipherMac.update((byte) (i4 >> 16));
                cBCBlockCipherMac.update((byte) (i4 >> 8));
                cBCBlockCipherMac.update((byte) i4);
                i3 = 6;
            }
            if (this.initialAssociatedText != null) {
                cBCBlockCipherMac.update(this.initialAssociatedText, 0, this.initialAssociatedText.length);
            }
            if (this.associatedText.size() > 0) {
                byte[] toByteArray = this.associatedText.toByteArray();
                cBCBlockCipherMac.update(toByteArray, 0, toByteArray.length);
            }
            i3 = (i3 + i4) % 16;
            if (i3 != 0) {
                while (i3 != 16) {
                    cBCBlockCipherMac.update((byte) 0);
                    i3++;
                }
            }
        }
        cBCBlockCipherMac.update(bArr, i, i2);
        return cBCBlockCipherMac.doFinal(bArr2, 0);
    }

    private int getAssociatedTextLength() {
        return (this.initialAssociatedText == null ? 0 : this.initialAssociatedText.length) + this.associatedText.size();
    }

    private boolean hasAssociatedText() {
        return getAssociatedTextLength() > 0;
    }

    public int doFinal(byte[] bArr, int i) throws IllegalStateException, InvalidCipherTextException {
        byte[] toByteArray = this.data.toByteArray();
        Object processPacket = processPacket(toByteArray, 0, toByteArray.length);
        System.arraycopy(processPacket, 0, bArr, i, processPacket.length);
        reset();
        return processPacket.length;
    }

    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/CCM";
    }

    public byte[] getMac() {
        Object obj = new byte[this.macSize];
        System.arraycopy(this.macBlock, 0, obj, 0, obj.length);
        return obj;
    }

    public int getOutputSize(int i) {
        int size = this.data.size() + i;
        return this.forEncryption ? size + this.macSize : size < this.macSize ? 0 : size - this.macSize;
    }

    public BlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    public int getUpdateOutputSize(int i) {
        return 0;
    }

    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        this.forEncryption = z;
        if (cipherParameters instanceof AEADParameters) {
            AEADParameters aEADParameters = (AEADParameters) cipherParameters;
            this.nonce = aEADParameters.getNonce();
            this.initialAssociatedText = aEADParameters.getAssociatedText();
            this.macSize = aEADParameters.getMacSize() / 8;
            this.keyParam = aEADParameters.getKey();
        } else if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            this.nonce = parametersWithIV.getIV();
            this.initialAssociatedText = null;
            this.macSize = this.macBlock.length / 2;
            this.keyParam = parametersWithIV.getParameters();
        } else {
            throw new IllegalArgumentException("invalid parameters passed to CCM");
        }
        if (this.nonce == null || this.nonce.length < 7 || this.nonce.length > 13) {
            throw new IllegalArgumentException("nonce must have length from 7 to 13 octets");
        }
    }

    public void processAADByte(byte b) {
        this.associatedText.write(b);
    }

    public void processAADBytes(byte[] bArr, int i, int i2) {
        this.associatedText.write(bArr, i, i2);
    }

    public int processByte(byte b, byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        this.data.write(b);
        return 0;
    }

    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException, IllegalStateException {
        this.data.write(bArr, i, i2);
        return 0;
    }

    public byte[] processPacket(byte[] bArr, int i, int i2) throws IllegalStateException, InvalidCipherTextException {
        if (this.keyParam == null) {
            throw new IllegalStateException("CCM cipher unitialized.");
        }
        int length = 15 - this.nonce.length;
        if (length >= 4 || i2 < (1 << (length * 8))) {
            Object obj = new byte[this.blockSize];
            obj[0] = (byte) ((length - 1) & 7);
            System.arraycopy(this.nonce, 0, obj, 1, this.nonce.length);
            BlockCipher sICBlockCipher = new SICBlockCipher(this.cipher);
            sICBlockCipher.init(this.forEncryption, new ParametersWithIV(this.keyParam, obj));
            Object obj2;
            if (this.forEncryption) {
                obj = new byte[(this.macSize + i2)];
                calculateMac(bArr, i, i2, this.macBlock);
                sICBlockCipher.processBlock(this.macBlock, 0, this.macBlock, 0);
                length = 0;
                while (i < i2 - this.blockSize) {
                    sICBlockCipher.processBlock(bArr, i, obj, length);
                    length += this.blockSize;
                    i += this.blockSize;
                }
                obj2 = new byte[this.blockSize];
                System.arraycopy(bArr, i, obj2, 0, i2 - i);
                sICBlockCipher.processBlock(obj2, 0, obj2, 0);
                System.arraycopy(obj2, 0, obj, length, i2 - i);
                length += i2 - i;
                System.arraycopy(this.macBlock, 0, obj, length, obj.length - length);
                return obj;
            }
            obj = new byte[(i2 - this.macSize)];
            System.arraycopy(bArr, (i + i2) - this.macSize, this.macBlock, 0, this.macSize);
            sICBlockCipher.processBlock(this.macBlock, 0, this.macBlock, 0);
            for (length = this.macSize; length != this.macBlock.length; length++) {
                this.macBlock[length] = (byte) 0;
            }
            length = 0;
            while (length < obj.length - this.blockSize) {
                sICBlockCipher.processBlock(bArr, i, obj, length);
                length += this.blockSize;
                i += this.blockSize;
            }
            obj2 = new byte[this.blockSize];
            System.arraycopy(bArr, i, obj2, 0, obj.length - length);
            sICBlockCipher.processBlock(obj2, 0, obj2, 0);
            System.arraycopy(obj2, 0, obj, length, obj.length - length);
            byte[] bArr2 = new byte[this.blockSize];
            calculateMac(obj, 0, obj.length, bArr2);
            if (Arrays.constantTimeAreEqual(this.macBlock, bArr2)) {
                return obj;
            }
            throw new InvalidCipherTextException("mac check in CCM failed");
        }
        throw new IllegalStateException("CCM packet too large for choice of q.");
    }

    public void reset() {
        this.cipher.reset();
        this.associatedText.reset();
        this.data.reset();
    }
}
