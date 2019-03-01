package org.bouncycastle.crypto.digests;

import org.bouncycastle.asn1.eac.CertificateBody;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;

public final class WhirlpoolDigest implements ExtendedDigest, Memoable {
    private static final int BITCOUNT_ARRAY_SIZE = 32;
    private static final int BYTE_LENGTH = 64;
    private static final long[] C0 = new long[256];
    private static final long[] C1 = new long[256];
    private static final long[] C2 = new long[256];
    private static final long[] C3 = new long[256];
    private static final long[] C4 = new long[256];
    private static final long[] C5 = new long[256];
    private static final long[] C6 = new long[256];
    private static final long[] C7 = new long[256];
    private static final int DIGEST_LENGTH_BYTES = 64;
    private static final short[] EIGHT = new short[32];
    private static final int REDUCTION_POLYNOMIAL = 285;
    private static final int ROUNDS = 10;
    private static final int[] SBOX = new int[]{24, 35, 198, 232, CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA, 184, 1, 79, 54, CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256, 210, 245, EACTags.COEXISTANT_TAG_ALLOCATION_AUTHORITY, EACTags.FCI_TEMPLATE, 145, 82, 96, 188, CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA, 142, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, 12, EACTags.SECURITY_ENVIRONMENT_TEMPLATE, 53, 29, 224, 215, 194, 46, 75, 254, 87, 21, 119, 55, 229, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, 240, 74, 218, 88, 201, 41, 10, 177, CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, 107, CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA, 189, 93, 16, 244, 203, 62, 5, 103, 228, 39, 65, 139, CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384, EACTags.SECURE_MESSAGING_TEMPLATE, 149, 216, 251, 238, EACTags.DYNAMIC_AUTHENTIFICATION_TEMPLATE, EACTags.CARD_DATA, 221, 23, 71, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, 202, 45, 191, 7, 173, 90, 131, 51, 99, 2, 170, 113, 200, 25, 73, 217, 242, 227, 91, CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA, CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA, 38, 50, 176, 233, 15, 213, 128, 190, 205, 52, 72, 255, EACTags.SECURITY_SUPPORT_TEMPLATE, 144, 95, 32, 104, 26, 174, 180, 84, 147, 34, 100, 241, EACTags.DISCRETIONARY_DATA_OBJECTS, 18, 64, 8, 195, 236, 219, CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384, 141, 61, CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA, 0, 207, 43, 118, 130, 214, 27, 181, 175, 106, 80, 69, 243, 48, 239, 63, 85, CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, 234, EACTags.CARDHOLDER_RELATIVE_DATA, 186, 47, 192, 222, 28, 253, 77, 146, 117, 6, 138, 178, 230, 14, 31, 98, 212, 168, CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA, 249, 197, 37, 89, CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA, 114, 57, 76, 94, EACTags.COMPATIBLE_TAG_ALLOCATION_AUTHORITY, 56, 140, 209, CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384, 226, 97, 179, 33, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, 30, 67, 199, 252, 4, 81, CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA, 109, 13, 250, 223, EACTags.NON_INTERINDUSTRY_DATA_OBJECT_NESTING_TEMPLATE, 36, 59, 171, 206, 17, 143, 78, 183, 235, 60, 129, 148, 247, 185, 19, 44, 211, 231, EACTags.APPLICATION_RELATED_DATA, 196, 3, 86, 68, CertificateBody.profileType, 169, 42, 187, 193, 83, 220, 11, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, 108, 49, 116, 246, 70, 172, CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA, 20, 225, 22, 58, CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256, 9, 112, 182, 208, 237, 204, 66, CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA, CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256, 40, 92, 248, CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA};
    private long[] _K;
    private long[] _L;
    private short[] _bitCount;
    private long[] _block;
    private byte[] _buffer;
    private int _bufferPos;
    private long[] _hash;
    private final long[] _rc;
    private long[] _state;

    static {
        EIGHT[31] = (short) 8;
    }

    public WhirlpoolDigest() {
        this._rc = new long[11];
        this._buffer = new byte[64];
        this._bufferPos = 0;
        this._bitCount = new short[32];
        this._hash = new long[8];
        this._K = new long[8];
        this._L = new long[8];
        this._block = new long[8];
        this._state = new long[8];
        for (int i = 0; i < 256; i++) {
            int i2 = SBOX[i];
            int maskWithReductionPolynomial = maskWithReductionPolynomial(i2 << 1);
            int maskWithReductionPolynomial2 = maskWithReductionPolynomial(maskWithReductionPolynomial << 1);
            int i3 = maskWithReductionPolynomial2 ^ i2;
            int maskWithReductionPolynomial3 = maskWithReductionPolynomial(maskWithReductionPolynomial2 << 1);
            int i4 = maskWithReductionPolynomial3 ^ i2;
            C0[i] = packIntoLong(i2, i2, maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3, i3, maskWithReductionPolynomial, i4);
            C1[i] = packIntoLong(i4, i2, i2, maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3, i3, maskWithReductionPolynomial);
            C2[i] = packIntoLong(maskWithReductionPolynomial, i4, i2, i2, maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3, i3);
            C3[i] = packIntoLong(i3, maskWithReductionPolynomial, i4, i2, i2, maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3);
            C4[i] = packIntoLong(maskWithReductionPolynomial3, i3, maskWithReductionPolynomial, i4, i2, i2, maskWithReductionPolynomial2, i2);
            C5[i] = packIntoLong(i2, maskWithReductionPolynomial3, i3, maskWithReductionPolynomial, i4, i2, i2, maskWithReductionPolynomial2);
            C6[i] = packIntoLong(maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3, i3, maskWithReductionPolynomial, i4, i2, i2);
            C7[i] = packIntoLong(i2, maskWithReductionPolynomial2, i2, maskWithReductionPolynomial3, i3, maskWithReductionPolynomial, i4, i2);
        }
        this._rc[0] = 0;
        for (int i5 = 1; i5 <= 10; i5++) {
            i2 = (i5 - 1) * 8;
            this._rc[i5] = (((((((C0[i2] & -72057594037927936L) ^ (C1[i2 + 1] & 71776119061217280L)) ^ (C2[i2 + 2] & 280375465082880L)) ^ (C3[i2 + 3] & 1095216660480L)) ^ (C4[i2 + 4] & 4278190080L)) ^ (C5[i2 + 5] & 16711680)) ^ (C6[i2 + 6] & 65280)) ^ (C7[i2 + 7] & 255);
        }
    }

    public WhirlpoolDigest(WhirlpoolDigest whirlpoolDigest) {
        this._rc = new long[11];
        this._buffer = new byte[64];
        this._bufferPos = 0;
        this._bitCount = new short[32];
        this._hash = new long[8];
        this._K = new long[8];
        this._L = new long[8];
        this._block = new long[8];
        this._state = new long[8];
        reset(whirlpoolDigest);
    }

    private long bytesToLongFromBuffer(byte[] bArr, int i) {
        return ((((((((((long) bArr[i + 0]) & 255) << 56) | ((((long) bArr[i + 1]) & 255) << 48)) | ((((long) bArr[i + 2]) & 255) << 40)) | ((((long) bArr[i + 3]) & 255) << 32)) | ((((long) bArr[i + 4]) & 255) << 24)) | ((((long) bArr[i + 5]) & 255) << 16)) | ((((long) bArr[i + 6]) & 255) << 8)) | (((long) bArr[i + 7]) & 255);
    }

    private void convertLongToByteArray(long j, byte[] bArr, int i) {
        for (int i2 = 0; i2 < 8; i2++) {
            bArr[i + i2] = (byte) ((int) ((j >> (56 - (i2 * 8))) & 255));
        }
    }

    private byte[] copyBitLength() {
        byte[] bArr = new byte[32];
        for (int i = 0; i < bArr.length; i++) {
            bArr[i] = (byte) (this._bitCount[i] & 255);
        }
        return bArr;
    }

    private void finish() {
        Object copyBitLength = copyBitLength();
        byte[] bArr = this._buffer;
        int i = this._bufferPos;
        this._bufferPos = i + 1;
        bArr[i] = (byte) (bArr[i] | 128);
        if (this._bufferPos == this._buffer.length) {
            processFilledBuffer(this._buffer, 0);
        }
        if (this._bufferPos > 32) {
            while (this._bufferPos != 0) {
                update((byte) 0);
            }
        }
        while (this._bufferPos <= 32) {
            update((byte) 0);
        }
        System.arraycopy(copyBitLength, 0, this._buffer, 32, copyBitLength.length);
        processFilledBuffer(this._buffer, 0);
    }

    private void increment() {
        int i = 0;
        for (int length = this._bitCount.length - 1; length >= 0; length--) {
            int i2 = ((this._bitCount[length] & 255) + EIGHT[length]) + i;
            i = i2 >>> 8;
            this._bitCount[length] = (short) (i2 & 255);
        }
    }

    private int maskWithReductionPolynomial(int i) {
        return ((long) i) >= 256 ? i ^ REDUCTION_POLYNOMIAL : i;
    }

    private long packIntoLong(int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        return (((((((((long) i) << 56) ^ (((long) i2) << 48)) ^ (((long) i3) << 40)) ^ (((long) i4) << 32)) ^ (((long) i5) << 24)) ^ (((long) i6) << 16)) ^ (((long) i7) << 8)) ^ ((long) i8);
    }

    private void processFilledBuffer(byte[] bArr, int i) {
        for (int i2 = 0; i2 < this._state.length; i2++) {
            this._block[i2] = bytesToLongFromBuffer(this._buffer, i2 * 8);
        }
        processBlock();
        this._bufferPos = 0;
        Arrays.fill(this._buffer, (byte) 0);
    }

    public Memoable copy() {
        return new WhirlpoolDigest(this);
    }

    public int doFinal(byte[] bArr, int i) {
        finish();
        for (int i2 = 0; i2 < 8; i2++) {
            convertLongToByteArray(this._hash[i2], bArr, (i2 * 8) + i);
        }
        reset();
        return getDigestSize();
    }

    public String getAlgorithmName() {
        return "Whirlpool";
    }

    public int getByteLength() {
        return 64;
    }

    public int getDigestSize() {
        return 64;
    }

    protected void processBlock() {
        int i;
        int i2 = 0;
        for (i = 0; i < 8; i++) {
            long[] jArr = this._state;
            long j = this._block[i];
            long[] jArr2 = this._K;
            long j2 = this._hash[i];
            jArr2[i] = j2;
            jArr[i] = j ^ j2;
        }
        for (int i3 = 1; i3 <= 10; i3++) {
            for (i = 0; i < 8; i++) {
                this._L[i] = 0;
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C0[((int) (this._K[(i + 0) & 7] >>> 56)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C1[((int) (this._K[(i - 1) & 7] >>> 48)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C2[((int) (this._K[(i - 2) & 7] >>> 40)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C3[((int) (this._K[(i - 3) & 7] >>> 32)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C4[((int) (this._K[(i - 4) & 7] >>> 24)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C5[((int) (this._K[(i - 5) & 7] >>> 16)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C6[((int) (this._K[(i - 6) & 7] >>> 8)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C7[((int) this._K[(i - 7) & 7]) & 255];
            }
            System.arraycopy(this._L, 0, this._K, 0, this._K.length);
            long[] jArr3 = this._K;
            jArr3[0] = jArr3[0] ^ this._rc[i3];
            for (i = 0; i < 8; i++) {
                this._L[i] = this._K[i];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C0[((int) (this._state[(i + 0) & 7] >>> 56)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C1[((int) (this._state[(i - 1) & 7] >>> 48)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C2[((int) (this._state[(i - 2) & 7] >>> 40)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C3[((int) (this._state[(i - 3) & 7] >>> 32)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C4[((int) (this._state[(i - 4) & 7] >>> 24)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C5[((int) (this._state[(i - 5) & 7] >>> 16)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C6[((int) (this._state[(i - 6) & 7] >>> 8)) & 255];
                jArr2 = this._L;
                jArr2[i] = jArr2[i] ^ C7[((int) this._state[(i - 7) & 7]) & 255];
            }
            System.arraycopy(this._L, 0, this._state, 0, this._state.length);
        }
        while (i2 < 8) {
            jArr3 = this._hash;
            jArr3[i2] = jArr3[i2] ^ (this._state[i2] ^ this._block[i2]);
            i2++;
        }
    }

    public void reset() {
        this._bufferPos = 0;
        Arrays.fill(this._bitCount, (short) 0);
        Arrays.fill(this._buffer, (byte) 0);
        Arrays.fill(this._hash, 0);
        Arrays.fill(this._K, 0);
        Arrays.fill(this._L, 0);
        Arrays.fill(this._block, 0);
        Arrays.fill(this._state, 0);
    }

    public void reset(Memoable memoable) {
        WhirlpoolDigest whirlpoolDigest = (WhirlpoolDigest) memoable;
        System.arraycopy(whirlpoolDigest._rc, 0, this._rc, 0, this._rc.length);
        System.arraycopy(whirlpoolDigest._buffer, 0, this._buffer, 0, this._buffer.length);
        this._bufferPos = whirlpoolDigest._bufferPos;
        System.arraycopy(whirlpoolDigest._bitCount, 0, this._bitCount, 0, this._bitCount.length);
        System.arraycopy(whirlpoolDigest._hash, 0, this._hash, 0, this._hash.length);
        System.arraycopy(whirlpoolDigest._K, 0, this._K, 0, this._K.length);
        System.arraycopy(whirlpoolDigest._L, 0, this._L, 0, this._L.length);
        System.arraycopy(whirlpoolDigest._block, 0, this._block, 0, this._block.length);
        System.arraycopy(whirlpoolDigest._state, 0, this._state, 0, this._state.length);
    }

    public void update(byte b) {
        this._buffer[this._bufferPos] = b;
        this._bufferPos++;
        if (this._bufferPos == this._buffer.length) {
            processFilledBuffer(this._buffer, 0);
        }
        increment();
    }

    public void update(byte[] bArr, int i, int i2) {
        while (i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
    }
}
