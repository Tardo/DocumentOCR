package org.bouncycastle.crypto.macs;

import custom.org.apache.harmony.xnet.provider.jsse.Handshake;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;

public class GOST28147Mac implements Mac {
    /* renamed from: S */
    private byte[] f255S = new byte[]{(byte) 9, (byte) 6, (byte) 3, (byte) 2, (byte) 8, (byte) 11, (byte) 1, (byte) 7, (byte) 10, (byte) 4, Handshake.SERVER_HELLO_DONE, Handshake.CERTIFICATE_VERIFY, (byte) 12, (byte) 0, (byte) 13, (byte) 5, (byte) 3, (byte) 7, Handshake.SERVER_HELLO_DONE, (byte) 9, (byte) 8, (byte) 10, Handshake.CERTIFICATE_VERIFY, (byte) 0, (byte) 5, (byte) 2, (byte) 6, (byte) 12, (byte) 11, (byte) 4, (byte) 13, (byte) 1, Handshake.SERVER_HELLO_DONE, (byte) 4, (byte) 6, (byte) 2, (byte) 11, (byte) 3, (byte) 13, (byte) 8, (byte) 12, Handshake.CERTIFICATE_VERIFY, (byte) 5, (byte) 10, (byte) 0, (byte) 7, (byte) 1, (byte) 9, Handshake.SERVER_HELLO_DONE, (byte) 7, (byte) 10, (byte) 12, (byte) 13, (byte) 1, (byte) 3, (byte) 9, (byte) 0, (byte) 2, (byte) 11, (byte) 4, Handshake.CERTIFICATE_VERIFY, (byte) 8, (byte) 5, (byte) 6, (byte) 11, (byte) 5, (byte) 1, (byte) 9, (byte) 8, (byte) 13, Handshake.CERTIFICATE_VERIFY, (byte) 0, Handshake.SERVER_HELLO_DONE, (byte) 4, (byte) 2, (byte) 3, (byte) 12, (byte) 7, (byte) 10, (byte) 6, (byte) 3, (byte) 10, (byte) 13, (byte) 12, (byte) 1, (byte) 2, (byte) 0, (byte) 11, (byte) 7, (byte) 5, (byte) 9, (byte) 4, (byte) 8, Handshake.CERTIFICATE_VERIFY, Handshake.SERVER_HELLO_DONE, (byte) 6, (byte) 1, (byte) 13, (byte) 2, (byte) 9, (byte) 7, (byte) 10, (byte) 6, (byte) 0, (byte) 8, (byte) 12, (byte) 4, (byte) 5, Handshake.CERTIFICATE_VERIFY, (byte) 3, (byte) 11, Handshake.SERVER_HELLO_DONE, (byte) 11, (byte) 10, Handshake.CERTIFICATE_VERIFY, (byte) 5, (byte) 0, (byte) 12, Handshake.SERVER_HELLO_DONE, (byte) 8, (byte) 6, (byte) 2, (byte) 3, (byte) 9, (byte) 1, (byte) 7, (byte) 13, (byte) 4};
    private int blockSize = 8;
    private byte[] buf = new byte[this.blockSize];
    private int bufOff = 0;
    private boolean firstStep = true;
    private byte[] mac = new byte[this.blockSize];
    private int macSize = 4;
    private int[] workingKey = null;

    private byte[] CM5func(byte[] bArr, int i, byte[] bArr2) {
        int i2 = 0;
        Object obj = new byte[(bArr.length - i)];
        System.arraycopy(bArr, i, obj, 0, bArr2.length);
        while (i2 != bArr2.length) {
            obj[i2] = (byte) (obj[i2] ^ bArr2[i2]);
            i2++;
        }
        return obj;
    }

    private int bytesToint(byte[] bArr, int i) {
        return ((((bArr[i + 3] << 24) & -16777216) + ((bArr[i + 2] << 16) & 16711680)) + ((bArr[i + 1] << 8) & 65280)) + (bArr[i] & 255);
    }

    private int[] generateWorkingKey(byte[] bArr) {
        if (bArr.length != 32) {
            throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
        }
        int[] iArr = new int[8];
        for (int i = 0; i != 8; i++) {
            iArr[i] = bytesToint(bArr, i * 4);
        }
        return iArr;
    }

    private void gost28147MacFunc(int[] iArr, byte[] bArr, int i, byte[] bArr2, int i2) {
        int bytesToint = bytesToint(bArr, i);
        int bytesToint2 = bytesToint(bArr, i + 4);
        int i3 = 0;
        while (i3 < 2) {
            int i4 = bytesToint2;
            bytesToint2 = 0;
            while (bytesToint2 < 8) {
                bytesToint2++;
                int i5 = bytesToint;
                bytesToint = i4 ^ gost28147_mainStep(bytesToint, iArr[bytesToint2]);
                i4 = i5;
            }
            i3++;
            bytesToint2 = i4;
        }
        intTobytes(bytesToint, bArr2, i2);
        intTobytes(bytesToint2, bArr2, i2 + 4);
    }

    private int gost28147_mainStep(int i, int i2) {
        int i3 = i2 + i;
        i3 = (this.f255S[((i3 >> 28) & 15) + 112] << 28) + (((((((this.f255S[((i3 >> 0) & 15) + 0] << 0) + (this.f255S[((i3 >> 4) & 15) + 16] << 4)) + (this.f255S[((i3 >> 8) & 15) + 32] << 8)) + (this.f255S[((i3 >> 12) & 15) + 48] << 12)) + (this.f255S[((i3 >> 16) & 15) + 64] << 16)) + (this.f255S[((i3 >> 20) & 15) + 80] << 20)) + (this.f255S[((i3 >> 24) & 15) + 96] << 24));
        return (i3 >>> 21) | (i3 << 11);
    }

    private void intTobytes(int i, byte[] bArr, int i2) {
        bArr[i2 + 3] = (byte) (i >>> 24);
        bArr[i2 + 2] = (byte) (i >>> 16);
        bArr[i2 + 1] = (byte) (i >>> 8);
        bArr[i2] = (byte) i;
    }

    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        while (this.bufOff < this.blockSize) {
            this.buf[this.bufOff] = (byte) 0;
            this.bufOff++;
        }
        byte[] bArr2 = new byte[this.buf.length];
        System.arraycopy(this.buf, 0, bArr2, 0, this.mac.length);
        if (this.firstStep) {
            this.firstStep = false;
        } else {
            bArr2 = CM5func(this.buf, 0, this.mac);
        }
        gost28147MacFunc(this.workingKey, bArr2, 0, this.mac, 0);
        System.arraycopy(this.mac, (this.mac.length / 2) - this.macSize, bArr, i, this.macSize);
        reset();
        return this.macSize;
    }

    public String getAlgorithmName() {
        return "GOST28147Mac";
    }

    public int getMacSize() {
        return this.macSize;
    }

    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        reset();
        this.buf = new byte[this.blockSize];
        if (cipherParameters instanceof ParametersWithSBox) {
            ParametersWithSBox parametersWithSBox = (ParametersWithSBox) cipherParameters;
            System.arraycopy(parametersWithSBox.getSBox(), 0, this.f255S, 0, parametersWithSBox.getSBox().length);
            if (parametersWithSBox.getParameters() != null) {
                this.workingKey = generateWorkingKey(((KeyParameter) parametersWithSBox.getParameters()).getKey());
            }
        } else if (cipherParameters instanceof KeyParameter) {
            this.workingKey = generateWorkingKey(((KeyParameter) cipherParameters).getKey());
        } else {
            throw new IllegalArgumentException("invalid parameter passed to GOST28147 init - " + cipherParameters.getClass().getName());
        }
    }

    public void reset() {
        for (int i = 0; i < this.buf.length; i++) {
            this.buf[i] = (byte) 0;
        }
        this.bufOff = 0;
        this.firstStep = true;
    }

    public void update(byte b) throws IllegalStateException {
        if (this.bufOff == this.buf.length) {
            byte[] bArr = new byte[this.buf.length];
            System.arraycopy(this.buf, 0, bArr, 0, this.mac.length);
            if (this.firstStep) {
                this.firstStep = false;
            } else {
                bArr = CM5func(this.buf, 0, this.mac);
            }
            gost28147MacFunc(this.workingKey, bArr, 0, this.mac, 0);
            this.bufOff = 0;
        }
        byte[] bArr2 = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr2[i] = b;
    }

    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        if (i2 < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }
        int i3;
        int i4 = this.blockSize - this.bufOff;
        if (i2 > i4) {
            System.arraycopy(bArr, i, this.buf, this.bufOff, i4);
            byte[] bArr2 = new byte[this.buf.length];
            System.arraycopy(this.buf, 0, bArr2, 0, this.mac.length);
            if (this.firstStep) {
                this.firstStep = false;
            } else {
                bArr2 = CM5func(this.buf, 0, this.mac);
            }
            gost28147MacFunc(this.workingKey, bArr2, 0, this.mac, 0);
            this.bufOff = 0;
            int i5 = i + i4;
            i4 = i2 - i4;
            i3 = i5;
            while (i4 > this.blockSize) {
                gost28147MacFunc(this.workingKey, CM5func(bArr, i3, this.mac), 0, this.mac, 0);
                i4 -= this.blockSize;
                i3 = this.blockSize + i3;
            }
        } else {
            i4 = i2;
            i3 = i;
        }
        System.arraycopy(bArr, i3, this.buf, this.bufOff, i4);
        this.bufOff += i4;
    }
}
