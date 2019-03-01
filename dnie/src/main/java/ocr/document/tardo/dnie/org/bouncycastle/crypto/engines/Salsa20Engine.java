package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.MaxBytesExceededException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.util.Pack;
import org.bouncycastle.util.Strings;

public class Salsa20Engine implements StreamCipher {
    private static final int STATE_SIZE = 16;
    private static final byte[] sigma = Strings.toByteArray("expand 32-byte k");
    private static final byte[] tau = Strings.toByteArray("expand 16-byte k");
    private int cW0;
    private int cW1;
    private int cW2;
    private int[] engineState = new int[16];
    private int index = 0;
    private boolean initialised = false;
    private byte[] keyStream = new byte[64];
    private byte[] workingIV = null;
    private byte[] workingKey = null;
    /* renamed from: x */
    private int[] f247x = new int[16];

    private void generateKeyStream(byte[] bArr) {
        salsaCore(20, this.engineState, this.f247x);
        Pack.intToLittleEndian(this.f247x, bArr, 0);
    }

    private boolean limitExceeded() {
        int i = this.cW0 + 1;
        this.cW0 = i;
        if (i != 0) {
            return false;
        }
        i = this.cW1 + 1;
        this.cW1 = i;
        if (i != 0) {
            return false;
        }
        i = this.cW2 + 1;
        this.cW2 = i;
        return (i & 32) != 0;
    }

    private boolean limitExceeded(int i) {
        this.cW0 += i;
        if (this.cW0 >= i || this.cW0 < 0) {
            return false;
        }
        int i2 = this.cW1 + 1;
        this.cW1 = i2;
        if (i2 != 0) {
            return false;
        }
        i2 = this.cW2 + 1;
        this.cW2 = i2;
        return (i2 & 32) != 0;
    }

    private void resetCounter() {
        this.cW0 = 0;
        this.cW1 = 0;
        this.cW2 = 0;
    }

    private static int rotl(int i, int i2) {
        return (i << i2) | (i >>> (-i2));
    }

    public static void salsaCore(int i, int[] iArr, int[] iArr2) {
        int i2 = 0;
        System.arraycopy(iArr, 0, iArr2, 0, iArr.length);
        while (i > 0) {
            iArr2[4] = iArr2[4] ^ rotl(iArr2[0] + iArr2[12], 7);
            iArr2[8] = iArr2[8] ^ rotl(iArr2[4] + iArr2[0], 9);
            iArr2[12] = iArr2[12] ^ rotl(iArr2[8] + iArr2[4], 13);
            iArr2[0] = iArr2[0] ^ rotl(iArr2[12] + iArr2[8], 18);
            iArr2[9] = iArr2[9] ^ rotl(iArr2[5] + iArr2[1], 7);
            iArr2[13] = iArr2[13] ^ rotl(iArr2[9] + iArr2[5], 9);
            iArr2[1] = iArr2[1] ^ rotl(iArr2[13] + iArr2[9], 13);
            iArr2[5] = iArr2[5] ^ rotl(iArr2[1] + iArr2[13], 18);
            iArr2[14] = iArr2[14] ^ rotl(iArr2[10] + iArr2[6], 7);
            iArr2[2] = iArr2[2] ^ rotl(iArr2[14] + iArr2[10], 9);
            iArr2[6] = iArr2[6] ^ rotl(iArr2[2] + iArr2[14], 13);
            iArr2[10] = iArr2[10] ^ rotl(iArr2[6] + iArr2[2], 18);
            iArr2[3] = iArr2[3] ^ rotl(iArr2[15] + iArr2[11], 7);
            iArr2[7] = iArr2[7] ^ rotl(iArr2[3] + iArr2[15], 9);
            iArr2[11] = iArr2[11] ^ rotl(iArr2[7] + iArr2[3], 13);
            iArr2[15] = iArr2[15] ^ rotl(iArr2[11] + iArr2[7], 18);
            iArr2[1] = iArr2[1] ^ rotl(iArr2[0] + iArr2[3], 7);
            iArr2[2] = iArr2[2] ^ rotl(iArr2[1] + iArr2[0], 9);
            iArr2[3] = iArr2[3] ^ rotl(iArr2[2] + iArr2[1], 13);
            iArr2[0] = iArr2[0] ^ rotl(iArr2[3] + iArr2[2], 18);
            iArr2[6] = iArr2[6] ^ rotl(iArr2[5] + iArr2[4], 7);
            iArr2[7] = iArr2[7] ^ rotl(iArr2[6] + iArr2[5], 9);
            iArr2[4] = iArr2[4] ^ rotl(iArr2[7] + iArr2[6], 13);
            iArr2[5] = iArr2[5] ^ rotl(iArr2[4] + iArr2[7], 18);
            iArr2[11] = iArr2[11] ^ rotl(iArr2[10] + iArr2[9], 7);
            iArr2[8] = iArr2[8] ^ rotl(iArr2[11] + iArr2[10], 9);
            iArr2[9] = iArr2[9] ^ rotl(iArr2[8] + iArr2[11], 13);
            iArr2[10] = iArr2[10] ^ rotl(iArr2[9] + iArr2[8], 18);
            iArr2[12] = iArr2[12] ^ rotl(iArr2[15] + iArr2[14], 7);
            iArr2[13] = iArr2[13] ^ rotl(iArr2[12] + iArr2[15], 9);
            iArr2[14] = iArr2[14] ^ rotl(iArr2[13] + iArr2[12], 13);
            iArr2[15] = iArr2[15] ^ rotl(iArr2[14] + iArr2[13], 18);
            i -= 2;
        }
        while (i2 < 16) {
            iArr2[i2] = iArr2[i2] + iArr[i2];
            i2++;
        }
    }

    private void setKey(byte[] bArr, byte[] bArr2) {
        byte[] bArr3;
        int i;
        this.workingKey = bArr;
        this.workingIV = bArr2;
        this.index = 0;
        resetCounter();
        this.engineState[1] = Pack.littleEndianToInt(this.workingKey, 0);
        this.engineState[2] = Pack.littleEndianToInt(this.workingKey, 4);
        this.engineState[3] = Pack.littleEndianToInt(this.workingKey, 8);
        this.engineState[4] = Pack.littleEndianToInt(this.workingKey, 12);
        if (this.workingKey.length == 32) {
            bArr3 = sigma;
            i = 16;
        } else {
            bArr3 = tau;
            i = 0;
        }
        this.engineState[11] = Pack.littleEndianToInt(this.workingKey, i);
        this.engineState[12] = Pack.littleEndianToInt(this.workingKey, i + 4);
        this.engineState[13] = Pack.littleEndianToInt(this.workingKey, i + 8);
        this.engineState[14] = Pack.littleEndianToInt(this.workingKey, i + 12);
        this.engineState[0] = Pack.littleEndianToInt(bArr3, 0);
        this.engineState[5] = Pack.littleEndianToInt(bArr3, 4);
        this.engineState[10] = Pack.littleEndianToInt(bArr3, 8);
        this.engineState[15] = Pack.littleEndianToInt(bArr3, 12);
        this.engineState[6] = Pack.littleEndianToInt(this.workingIV, 0);
        this.engineState[7] = Pack.littleEndianToInt(this.workingIV, 4);
        int[] iArr = this.engineState;
        this.engineState[9] = 0;
        iArr[8] = 0;
        this.initialised = true;
    }

    public String getAlgorithmName() {
        return "Salsa20";
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            byte[] iv = parametersWithIV.getIV();
            if (iv == null || iv.length != 8) {
                throw new IllegalArgumentException("Salsa20 requires exactly 8 bytes of IV");
            } else if (parametersWithIV.getParameters() instanceof KeyParameter) {
                this.workingKey = ((KeyParameter) parametersWithIV.getParameters()).getKey();
                this.workingIV = iv;
                setKey(this.workingKey, this.workingIV);
                return;
            } else {
                throw new IllegalArgumentException("Salsa20 Init parameters must include a key");
            }
        }
        throw new IllegalArgumentException("Salsa20 Init parameters must include an IV");
    }

    public void processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        if (!this.initialised) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        } else if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        } else if (i3 + i2 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        } else if (limitExceeded(i2)) {
            throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
        } else {
            for (int i4 = 0; i4 < i2; i4++) {
                if (this.index == 0) {
                    generateKeyStream(this.keyStream);
                    int[] iArr = this.engineState;
                    int i5 = iArr[8] + 1;
                    iArr[8] = i5;
                    if (i5 == 0) {
                        iArr = this.engineState;
                        iArr[9] = iArr[9] + 1;
                    }
                }
                bArr2[i4 + i3] = (byte) (this.keyStream[this.index] ^ bArr[i4 + i]);
                this.index = (this.index + 1) & 63;
            }
        }
    }

    public void reset() {
        setKey(this.workingKey, this.workingIV);
    }

    public byte returnByte(byte b) {
        if (limitExceeded()) {
            throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
        }
        if (this.index == 0) {
            generateKeyStream(this.keyStream);
            int[] iArr = this.engineState;
            int i = iArr[8] + 1;
            iArr[8] = i;
            if (i == 0) {
                iArr = this.engineState;
                iArr[9] = iArr[9] + 1;
            }
        }
        byte b2 = (byte) (this.keyStream[this.index] ^ b);
        this.index = (this.index + 1) & 63;
        return b2;
    }
}
