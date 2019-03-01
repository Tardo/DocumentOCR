package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.Pack;
import org.bouncycastle.util.Arrays;

public class SipHash implements Mac {
    protected byte[] buf;
    protected int bufPos;
    /* renamed from: c */
    protected final int f256c;
    /* renamed from: d */
    protected final int f257d;
    protected long k0;
    protected long k1;
    protected long v0;
    protected long v1;
    protected long v2;
    protected long v3;
    protected long v4;
    protected int wordCount;

    public SipHash() {
        this.buf = new byte[8];
        this.bufPos = 0;
        this.wordCount = 0;
        this.f256c = 2;
        this.f257d = 4;
    }

    public SipHash(int i, int i2) {
        this.buf = new byte[8];
        this.bufPos = 0;
        this.wordCount = 0;
        this.f256c = i;
        this.f257d = i2;
    }

    protected static long rotateLeft(long j, int i) {
        return (j << i) | (j >>> (64 - i));
    }

    protected void applySipRounds(int i) {
        for (int i2 = 0; i2 < i; i2++) {
            this.v0 += this.v1;
            this.v2 += this.v3;
            this.v1 = rotateLeft(this.v1, 13);
            this.v3 = rotateLeft(this.v3, 16);
            this.v1 ^= this.v0;
            this.v3 ^= this.v2;
            this.v0 = rotateLeft(this.v0, 32);
            this.v2 += this.v1;
            this.v0 += this.v3;
            this.v1 = rotateLeft(this.v1, 17);
            this.v3 = rotateLeft(this.v3, 21);
            this.v1 ^= this.v2;
            this.v3 ^= this.v0;
            this.v2 = rotateLeft(this.v2, 32);
        }
    }

    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        Pack.longToLittleEndian(doFinal(), bArr, i);
        return 8;
    }

    public long doFinal() throws DataLengthException, IllegalStateException {
        this.buf[7] = (byte) (((this.wordCount << 3) + this.bufPos) & 255);
        while (this.bufPos < 7) {
            byte[] bArr = this.buf;
            int i = this.bufPos;
            this.bufPos = i + 1;
            bArr[i] = (byte) 0;
        }
        processMessageWord();
        this.v2 ^= 255;
        applySipRounds(this.f257d);
        long j = ((this.v0 ^ this.v1) ^ this.v2) ^ this.v3;
        reset();
        return j;
    }

    public String getAlgorithmName() {
        return "SipHash-" + this.f256c + "-" + this.f257d;
    }

    public int getMacSize() {
        return 8;
    }

    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        if (cipherParameters instanceof KeyParameter) {
            byte[] key = ((KeyParameter) cipherParameters).getKey();
            if (key.length != 16) {
                throw new IllegalArgumentException("'params' must be a 128-bit key");
            }
            this.k0 = Pack.littleEndianToLong(key, 0);
            this.k1 = Pack.littleEndianToLong(key, 8);
            reset();
            return;
        }
        throw new IllegalArgumentException("'params' must be an instance of KeyParameter");
    }

    protected void processMessageWord() {
        this.wordCount++;
        long littleEndianToLong = Pack.littleEndianToLong(this.buf, 0);
        this.v3 ^= littleEndianToLong;
        applySipRounds(this.f256c);
        this.v0 = littleEndianToLong ^ this.v0;
    }

    public void reset() {
        this.v0 = this.k0 ^ 8317987319222330741L;
        this.v1 = this.k1 ^ 7237128888997146477L;
        this.v2 = this.k0 ^ 7816392313619706465L;
        this.v3 = this.k1 ^ 8387220255154660723L;
        Arrays.fill(this.buf, (byte) 0);
        this.bufPos = 0;
        this.wordCount = 0;
    }

    public void update(byte b) throws IllegalStateException {
        this.buf[this.bufPos] = b;
        int i = this.bufPos + 1;
        this.bufPos = i;
        if (i == this.buf.length) {
            processMessageWord();
            this.bufPos = 0;
        }
    }

    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        for (int i3 = 0; i3 < i2; i3++) {
            this.buf[this.bufPos] = bArr[i + i3];
            int i4 = this.bufPos + 1;
            this.bufPos = i4;
            if (i4 == this.buf.length) {
                processMessageWord();
                this.bufPos = 0;
            }
        }
    }
}
