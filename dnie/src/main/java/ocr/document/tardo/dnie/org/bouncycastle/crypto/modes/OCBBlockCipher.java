package org.bouncycastle.crypto.modes;

import java.util.Vector;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.util.Arrays;

public class OCBBlockCipher implements AEADBlockCipher {
    private static final int BLOCK_SIZE = 16;
    private byte[] Checksum;
    /* renamed from: L */
    private Vector f265L;
    private byte[] L_Asterisk;
    private byte[] L_Dollar;
    private byte[] OffsetHASH;
    private byte[] OffsetMAIN;
    private byte[] OffsetMAIN_0;
    private byte[] Sum;
    private boolean forEncryption;
    private byte[] hashBlock;
    private long hashBlockCount;
    private int hashBlockPos;
    private BlockCipher hashCipher;
    private byte[] initialAssociatedText;
    private byte[] macBlock;
    private int macSize;
    private byte[] mainBlock;
    private long mainBlockCount;
    private int mainBlockPos;
    private BlockCipher mainCipher;

    public OCBBlockCipher(BlockCipher blockCipher, BlockCipher blockCipher2) {
        if (blockCipher == null) {
            throw new IllegalArgumentException("'hashCipher' cannot be null");
        } else if (blockCipher.getBlockSize() != 16) {
            throw new IllegalArgumentException("'hashCipher' must have a block size of 16");
        } else if (blockCipher2 == null) {
            throw new IllegalArgumentException("'mainCipher' cannot be null");
        } else if (blockCipher2.getBlockSize() != 16) {
            throw new IllegalArgumentException("'mainCipher' must have a block size of 16");
        } else if (blockCipher.getAlgorithmName().equals(blockCipher2.getAlgorithmName())) {
            this.hashCipher = blockCipher;
            this.mainCipher = blockCipher2;
        } else {
            throw new IllegalArgumentException("'hashCipher' and 'mainCipher' must be the same algorithm");
        }
    }

    protected static byte[] OCB_double(byte[] bArr) {
        byte[] bArr2 = new byte[16];
        bArr2[15] = (byte) ((CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA >>> ((1 - shiftLeft(bArr, bArr2)) << 3)) ^ bArr2[15]);
        return bArr2;
    }

    protected static void OCB_extend(byte[] bArr, int i) {
        bArr[i] = Byte.MIN_VALUE;
        while (true) {
            i++;
            if (i < 16) {
                bArr[i] = (byte) 0;
            } else {
                return;
            }
        }
    }

    protected static int OCB_ntz(long j) {
        if (j == 0) {
            return 64;
        }
        int i = 0;
        while ((1 & j) == 0) {
            i++;
            j >>= 1;
        }
        return i;
    }

    protected static int shiftLeft(byte[] bArr, byte[] bArr2) {
        int i = 16;
        int i2 = 0;
        while (true) {
            i--;
            if (i < 0) {
                return i2;
            }
            int i3 = bArr[i] & 255;
            bArr2[i] = (byte) (i2 | (i3 << 1));
            i2 = (i3 >>> 7) & 1;
        }
    }

    protected static void xor(byte[] bArr, byte[] bArr2) {
        for (int i = 15; i >= 0; i--) {
            bArr[i] = (byte) (bArr[i] ^ bArr2[i]);
        }
    }

    protected void clear(byte[] bArr) {
        if (bArr != null) {
            Arrays.fill(bArr, (byte) 0);
        }
    }

    public int doFinal(byte[] bArr, int i) throws IllegalStateException, InvalidCipherTextException {
        int i2;
        byte[] bArr2 = null;
        if (!this.forEncryption) {
            if (this.mainBlockPos < this.macSize) {
                throw new InvalidCipherTextException("data too short");
            }
            this.mainBlockPos -= this.macSize;
            bArr2 = new byte[this.macSize];
            System.arraycopy(this.mainBlock, this.mainBlockPos, bArr2, 0, this.macSize);
        }
        if (this.hashBlockPos > 0) {
            OCB_extend(this.hashBlock, this.hashBlockPos);
            updateHASH(this.L_Asterisk);
        }
        if (this.mainBlockPos > 0) {
            if (this.forEncryption) {
                OCB_extend(this.mainBlock, this.mainBlockPos);
                xor(this.Checksum, this.mainBlock);
            }
            xor(this.OffsetMAIN, this.L_Asterisk);
            byte[] bArr3 = new byte[16];
            this.hashCipher.processBlock(this.OffsetMAIN, 0, bArr3, 0);
            xor(this.mainBlock, bArr3);
            System.arraycopy(this.mainBlock, 0, bArr, i, this.mainBlockPos);
            if (!this.forEncryption) {
                OCB_extend(this.mainBlock, this.mainBlockPos);
                xor(this.Checksum, this.mainBlock);
            }
        }
        xor(this.Checksum, this.OffsetMAIN);
        xor(this.Checksum, this.L_Dollar);
        this.hashCipher.processBlock(this.Checksum, 0, this.Checksum, 0);
        xor(this.Checksum, this.Sum);
        this.macBlock = new byte[this.macSize];
        System.arraycopy(this.Checksum, 0, this.macBlock, 0, this.macSize);
        int i3 = this.mainBlockPos;
        if (this.forEncryption) {
            System.arraycopy(this.macBlock, 0, bArr, i + i3, this.macSize);
            i2 = this.macSize + i3;
        } else if (Arrays.constantTimeAreEqual(this.macBlock, bArr2)) {
            i2 = i3;
        } else {
            throw new InvalidCipherTextException("mac check in OCB failed");
        }
        reset(false);
        return i2;
    }

    public String getAlgorithmName() {
        return this.mainCipher.getAlgorithmName() + "/OCB";
    }

    protected byte[] getLSub(int i) {
        while (i >= this.f265L.size()) {
            this.f265L.addElement(OCB_double((byte[]) this.f265L.lastElement()));
        }
        return (byte[]) this.f265L.elementAt(i);
    }

    public byte[] getMac() {
        return Arrays.clone(this.macBlock);
    }

    public int getOutputSize(int i) {
        int i2 = this.mainBlockPos + i;
        return this.forEncryption ? i2 + this.macSize : i2 < this.macSize ? 0 : i2 - this.macSize;
    }

    public BlockCipher getUnderlyingCipher() {
        return this.mainCipher;
    }

    public int getUpdateOutputSize(int i) {
        int i2 = this.mainBlockPos + i;
        if (!this.forEncryption) {
            if (i2 < this.macSize) {
                return 0;
            }
            i2 -= this.macSize;
        }
        return i2 - (i2 % 16);
    }

    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        Object nonce;
        int macSize;
        this.forEncryption = z;
        this.macBlock = null;
        if (cipherParameters instanceof AEADParameters) {
            AEADParameters aEADParameters = (AEADParameters) cipherParameters;
            nonce = aEADParameters.getNonce();
            this.initialAssociatedText = aEADParameters.getAssociatedText();
            macSize = aEADParameters.getMacSize();
            if (macSize < 64 || macSize > 128 || macSize % 8 != 0) {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSize);
            }
            this.macSize = macSize / 8;
            CipherParameters key = aEADParameters.getKey();
        } else if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            Object iv = parametersWithIV.getIV();
            this.initialAssociatedText = null;
            this.macSize = 16;
            Object obj = iv;
            iv = (KeyParameter) parametersWithIV.getParameters();
            nonce = obj;
        } else {
            throw new IllegalArgumentException("invalid parameters passed to OCB");
        }
        this.hashBlock = new byte[16];
        this.mainBlock = new byte[(z ? 16 : this.macSize + 16)];
        if (nonce == null) {
            nonce = new byte[0];
        }
        if (nonce.length > 16 || (nonce.length == 16 && (nonce[0] & 128) != 0)) {
            throw new IllegalArgumentException("IV must be no more than 127 bits");
        }
        int i;
        if (key != null) {
            this.hashCipher.init(true, key);
            this.mainCipher.init(z, key);
            this.L_Asterisk = new byte[16];
            this.hashCipher.processBlock(this.L_Asterisk, 0, this.L_Asterisk, 0);
            this.L_Dollar = OCB_double(this.L_Asterisk);
            this.f265L = new Vector();
            this.f265L.addElement(OCB_double(this.L_Dollar));
            iv = new byte[16];
            System.arraycopy(nonce, 0, iv, iv.length - nonce.length, nonce.length);
        } else {
            this.hashCipher.init(true, key);
            this.mainCipher.init(z, key);
            this.L_Asterisk = new byte[16];
            this.hashCipher.processBlock(this.L_Asterisk, 0, this.L_Asterisk, 0);
            this.L_Dollar = OCB_double(this.L_Asterisk);
            this.f265L = new Vector();
            this.f265L.addElement(OCB_double(this.L_Dollar));
            iv = new byte[16];
            System.arraycopy(nonce, 0, iv, iv.length - nonce.length, nonce.length);
        }
        if (nonce.length == 16) {
            iv[0] = (byte) (iv[0] & 128);
        } else {
            iv[15 - nonce.length] = 1;
        }
        int i2 = iv[15] & 63;
        Object obj2 = new byte[16];
        iv[15] = (byte) (iv[15] & 192);
        this.hashCipher.processBlock(iv, 0, obj2, 0);
        Object obj3 = new byte[24];
        System.arraycopy(obj2, 0, obj3, 0, 16);
        for (i = 0; i < 8; i++) {
            obj3[i + 16] = (byte) (obj2[i] ^ obj2[i + 1]);
        }
        this.OffsetMAIN_0 = new byte[16];
        int i3 = i2 % 8;
        i = i2 / 8;
        if (i3 == 0) {
            System.arraycopy(obj3, i, this.OffsetMAIN_0, 0, 16);
        } else {
            macSize = i;
            for (i = 0; i < 16; i++) {
                i2 = obj3[macSize] & 255;
                macSize++;
                this.OffsetMAIN_0[i] = (byte) ((i2 << i3) | ((obj3[macSize] & 255) >>> (8 - i3)));
            }
        }
        this.hashBlockPos = 0;
        this.mainBlockPos = 0;
        this.hashBlockCount = 0;
        this.mainBlockCount = 0;
        this.OffsetHASH = new byte[16];
        this.Sum = new byte[16];
        this.OffsetMAIN = Arrays.clone(this.OffsetMAIN_0);
        this.Checksum = new byte[16];
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
    }

    public void processAADByte(byte b) {
        this.hashBlock[this.hashBlockPos] = b;
        int i = this.hashBlockPos + 1;
        this.hashBlockPos = i;
        if (i == this.hashBlock.length) {
            processHashBlock();
        }
    }

    public void processAADBytes(byte[] bArr, int i, int i2) {
        for (int i3 = 0; i3 < i2; i3++) {
            this.hashBlock[this.hashBlockPos] = bArr[i + i3];
            int i4 = this.hashBlockPos + 1;
            this.hashBlockPos = i4;
            if (i4 == this.hashBlock.length) {
                processHashBlock();
            }
        }
    }

    public int processByte(byte b, byte[] bArr, int i) throws DataLengthException {
        this.mainBlock[this.mainBlockPos] = b;
        int i2 = this.mainBlockPos + 1;
        this.mainBlockPos = i2;
        if (i2 != this.mainBlock.length) {
            return 0;
        }
        processMainBlock(bArr, i);
        return 16;
    }

    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        int i4 = 0;
        for (int i5 = 0; i5 < i2; i5++) {
            this.mainBlock[this.mainBlockPos] = bArr[i + i5];
            int i6 = this.mainBlockPos + 1;
            this.mainBlockPos = i6;
            if (i6 == this.mainBlock.length) {
                processMainBlock(bArr2, i3 + i4);
                i4 += 16;
            }
        }
        return i4;
    }

    protected void processHashBlock() {
        long j = this.hashBlockCount + 1;
        this.hashBlockCount = j;
        updateHASH(getLSub(OCB_ntz(j)));
        this.hashBlockPos = 0;
    }

    protected void processMainBlock(byte[] bArr, int i) {
        if (this.forEncryption) {
            xor(this.Checksum, this.mainBlock);
            this.mainBlockPos = 0;
        }
        byte[] bArr2 = this.OffsetMAIN;
        long j = this.mainBlockCount + 1;
        this.mainBlockCount = j;
        xor(bArr2, getLSub(OCB_ntz(j)));
        xor(this.mainBlock, this.OffsetMAIN);
        this.mainCipher.processBlock(this.mainBlock, 0, this.mainBlock, 0);
        xor(this.mainBlock, this.OffsetMAIN);
        System.arraycopy(this.mainBlock, 0, bArr, i, 16);
        if (!this.forEncryption) {
            xor(this.Checksum, this.mainBlock);
            System.arraycopy(this.mainBlock, 16, this.mainBlock, 0, this.macSize);
            this.mainBlockPos = this.macSize;
        }
    }

    public void reset() {
        reset(true);
    }

    protected void reset(boolean z) {
        this.hashCipher.reset();
        this.mainCipher.reset();
        clear(this.hashBlock);
        clear(this.mainBlock);
        this.hashBlockPos = 0;
        this.mainBlockPos = 0;
        this.hashBlockCount = 0;
        this.mainBlockCount = 0;
        clear(this.OffsetHASH);
        clear(this.Sum);
        System.arraycopy(this.OffsetMAIN_0, 0, this.OffsetMAIN, 0, 16);
        clear(this.Checksum);
        if (z) {
            this.macBlock = null;
        }
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
    }

    protected void updateHASH(byte[] bArr) {
        xor(this.OffsetHASH, bArr);
        xor(this.hashBlock, this.OffsetHASH);
        this.hashCipher.processBlock(this.hashBlock, 0, this.hashBlock, 0);
        xor(this.Sum, this.hashBlock);
    }
}
