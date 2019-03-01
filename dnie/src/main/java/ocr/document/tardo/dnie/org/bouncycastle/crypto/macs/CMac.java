package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;

public class CMac implements Mac {
    private static final byte CONSTANT_128 = (byte) -121;
    private static final byte CONSTANT_64 = (byte) 27;
    /* renamed from: L */
    private byte[] f254L;
    private byte[] Lu;
    private byte[] Lu2;
    private byte[] ZEROES;
    private byte[] buf;
    private int bufOff;
    private BlockCipher cipher;
    private byte[] mac;
    private int macSize;

    public CMac(BlockCipher blockCipher) {
        this(blockCipher, blockCipher.getBlockSize() * 8);
    }

    public CMac(BlockCipher blockCipher, int i) {
        if (i % 8 != 0) {
            throw new IllegalArgumentException("MAC size must be multiple of 8");
        } else if (i > blockCipher.getBlockSize() * 8) {
            throw new IllegalArgumentException("MAC size must be less or equal to " + (blockCipher.getBlockSize() * 8));
        } else if (blockCipher.getBlockSize() == 8 || blockCipher.getBlockSize() == 16) {
            this.cipher = new CBCBlockCipher(blockCipher);
            this.macSize = i / 8;
            this.mac = new byte[blockCipher.getBlockSize()];
            this.buf = new byte[blockCipher.getBlockSize()];
            this.ZEROES = new byte[blockCipher.getBlockSize()];
            this.bufOff = 0;
        } else {
            throw new IllegalArgumentException("Block size must be either 64 or 128 bits");
        }
    }

    private static byte[] doubleLu(byte[] bArr) {
        int i = 0;
        int i2 = (bArr[0] & 255) >> 7;
        byte[] bArr2 = new byte[bArr.length];
        while (i < bArr.length - 1) {
            bArr2[i] = (byte) ((bArr[i] << 1) + ((bArr[i + 1] & 255) >> 7));
            i++;
        }
        bArr2[bArr.length - 1] = (byte) (bArr[bArr.length - 1] << 1);
        if (i2 == 1) {
            i2 = bArr.length - 1;
            bArr2[i2] = (byte) ((bArr.length == 16 ? -121 : 27) ^ bArr2[i2]);
        }
        return bArr2;
    }

    public int doFinal(byte[] bArr, int i) {
        byte[] bArr2;
        if (this.bufOff == this.cipher.getBlockSize()) {
            bArr2 = this.Lu;
        } else {
            new ISO7816d4Padding().addPadding(this.buf, this.bufOff);
            bArr2 = this.Lu2;
        }
        for (int i2 = 0; i2 < this.mac.length; i2++) {
            byte[] bArr3 = this.buf;
            bArr3[i2] = (byte) (bArr3[i2] ^ bArr2[i2]);
        }
        this.cipher.processBlock(this.buf, 0, this.mac, 0);
        System.arraycopy(this.mac, 0, bArr, i, this.macSize);
        reset();
        return this.macSize;
    }

    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName();
    }

    public int getMacSize() {
        return this.macSize;
    }

    public void init(CipherParameters cipherParameters) {
        if (cipherParameters != null) {
            this.cipher.init(true, cipherParameters);
            this.f254L = new byte[this.ZEROES.length];
            this.cipher.processBlock(this.ZEROES, 0, this.f254L, 0);
            this.Lu = doubleLu(this.f254L);
            this.Lu2 = doubleLu(this.Lu);
        }
        reset();
    }

    public void reset() {
        for (int i = 0; i < this.buf.length; i++) {
            this.buf[i] = (byte) 0;
        }
        this.bufOff = 0;
        this.cipher.reset();
    }

    public void update(byte b) {
        if (this.bufOff == this.buf.length) {
            this.cipher.processBlock(this.buf, 0, this.mac, 0);
            this.bufOff = 0;
        }
        byte[] bArr = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr[i] = b;
    }

    public void update(byte[] bArr, int i, int i2) {
        if (i2 < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }
        int blockSize = this.cipher.getBlockSize();
        int i3 = blockSize - this.bufOff;
        if (i2 > i3) {
            System.arraycopy(bArr, i, this.buf, this.bufOff, i3);
            this.cipher.processBlock(this.buf, 0, this.mac, 0);
            this.bufOff = 0;
            i2 -= i3;
            i += i3;
            while (i2 > blockSize) {
                this.cipher.processBlock(bArr, i, this.mac, 0);
                i2 -= blockSize;
                i += blockSize;
            }
        }
        System.arraycopy(bArr, i, this.buf, this.bufOff, i2);
        this.bufOff += i2;
    }
}
