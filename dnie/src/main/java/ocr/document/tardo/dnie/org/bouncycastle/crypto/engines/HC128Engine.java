package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class HC128Engine implements StreamCipher {
    private byte[] buf = new byte[4];
    private int cnt = 0;
    private int idx = 0;
    private boolean initialised;
    private byte[] iv;
    private byte[] key;
    /* renamed from: p */
    private int[] f237p = new int[512];
    /* renamed from: q */
    private int[] f238q = new int[512];

    private static int dim(int i, int i2) {
        return mod512(i - i2);
    }

    private static int f1(int i) {
        return (rotateRight(i, 7) ^ rotateRight(i, 18)) ^ (i >>> 3);
    }

    private static int f2(int i) {
        return (rotateRight(i, 17) ^ rotateRight(i, 19)) ^ (i >>> 10);
    }

    private int g1(int i, int i2, int i3) {
        return (rotateRight(i, 10) ^ rotateRight(i3, 23)) + rotateRight(i2, 8);
    }

    private int g2(int i, int i2, int i3) {
        return (rotateLeft(i, 10) ^ rotateLeft(i3, 23)) + rotateLeft(i2, 8);
    }

    private byte getByte() {
        if (this.idx == 0) {
            int step = step();
            this.buf[0] = (byte) (step & 255);
            step >>= 8;
            this.buf[1] = (byte) (step & 255);
            step >>= 8;
            this.buf[2] = (byte) (step & 255);
            this.buf[3] = (byte) ((step >> 8) & 255);
        }
        byte b = this.buf[this.idx];
        this.idx = (this.idx + 1) & 3;
        return b;
    }

    private int h1(int i) {
        return this.f238q[i & 255] + this.f238q[((i >> 16) & 255) + 256];
    }

    private int h2(int i) {
        return this.f237p[i & 255] + this.f237p[((i >> 16) & 255) + 256];
    }

    private void init() {
        if (this.key.length != 16) {
            throw new IllegalArgumentException("The key must be 128 bits long");
        }
        int i;
        this.cnt = 0;
        Object obj = new int[1280];
        for (i = 0; i < 16; i++) {
            int i2 = i >> 2;
            obj[i2] = obj[i2] | ((this.key[i] & 255) << ((i & 3) * 8));
        }
        System.arraycopy(obj, 0, obj, 4, 4);
        i = 0;
        while (i < this.iv.length && i < 16) {
            i2 = (i >> 2) + 8;
            obj[i2] = obj[i2] | ((this.iv[i] & 255) << ((i & 3) * 8));
            i++;
        }
        System.arraycopy(obj, 8, obj, 12, 4);
        for (i = 16; i < 1280; i++) {
            obj[i] = (((f2(obj[i - 2]) + obj[i - 7]) + f1(obj[i - 15])) + obj[i - 16]) + i;
        }
        System.arraycopy(obj, 256, this.f237p, 0, 512);
        System.arraycopy(obj, 768, this.f238q, 0, 512);
        for (i = 0; i < 512; i++) {
            this.f237p[i] = step();
        }
        for (i = 0; i < 512; i++) {
            this.f238q[i] = step();
        }
        this.cnt = 0;
    }

    private static int mod1024(int i) {
        return i & 1023;
    }

    private static int mod512(int i) {
        return i & 511;
    }

    private static int rotateLeft(int i, int i2) {
        return (i << i2) | (i >>> (-i2));
    }

    private static int rotateRight(int i, int i2) {
        return (i >>> i2) | (i << (-i2));
    }

    private int step() {
        int mod512 = mod512(this.cnt);
        int[] iArr;
        if (this.cnt < 512) {
            iArr = this.f237p;
            iArr[mod512] = iArr[mod512] + g1(this.f237p[dim(mod512, 3)], this.f237p[dim(mod512, 10)], this.f237p[dim(mod512, 511)]);
            mod512 = this.f237p[mod512] ^ h1(this.f237p[dim(mod512, 12)]);
        } else {
            iArr = this.f238q;
            iArr[mod512] = iArr[mod512] + g2(this.f238q[dim(mod512, 3)], this.f238q[dim(mod512, 10)], this.f238q[dim(mod512, 511)]);
            mod512 = this.f238q[mod512] ^ h2(this.f238q[dim(mod512, 12)]);
        }
        this.cnt = mod1024(this.cnt + 1);
        return mod512;
    }

    public String getAlgorithmName() {
        return "HC-128";
    }

    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        CipherParameters parameters;
        if (cipherParameters instanceof ParametersWithIV) {
            this.iv = ((ParametersWithIV) cipherParameters).getIV();
            parameters = ((ParametersWithIV) cipherParameters).getParameters();
        } else {
            this.iv = new byte[0];
            parameters = cipherParameters;
        }
        if (parameters instanceof KeyParameter) {
            this.key = ((KeyParameter) parameters).getKey();
            init();
            this.initialised = true;
            return;
        }
        throw new IllegalArgumentException("Invalid parameter passed to HC128 init - " + cipherParameters.getClass().getName());
    }

    public void processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        if (!this.initialised) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        } else if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        } else if (i3 + i2 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            for (int i4 = 0; i4 < i2; i4++) {
                bArr2[i3 + i4] = (byte) (bArr[i + i4] ^ getByte());
            }
        }
    }

    public void reset() {
        this.idx = 0;
        init();
    }

    public byte returnByte(byte b) {
        return (byte) (getByte() ^ b);
    }
}
