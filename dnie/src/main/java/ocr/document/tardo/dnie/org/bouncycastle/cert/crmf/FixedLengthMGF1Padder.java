package org.bouncycastle.cert.crmf;

import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.MGF1BytesGenerator;
import org.bouncycastle.crypto.params.MGFParameters;

public class FixedLengthMGF1Padder implements EncryptedValuePadder {
    private Digest dig;
    private int length;
    private SecureRandom random;

    public FixedLengthMGF1Padder(int i) {
        this(i, null);
    }

    public FixedLengthMGF1Padder(int i, SecureRandom secureRandom) {
        this.dig = new SHA1Digest();
        this.length = i;
        this.random = secureRandom;
    }

    public byte[] getPaddedData(byte[] bArr) {
        int length;
        Object obj = new byte[this.length];
        Object obj2 = new byte[this.dig.getDigestSize()];
        byte[] bArr2 = new byte[(this.length - this.dig.getDigestSize())];
        if (this.random == null) {
            this.random = new SecureRandom();
        }
        this.random.nextBytes(obj2);
        MGF1BytesGenerator mGF1BytesGenerator = new MGF1BytesGenerator(this.dig);
        mGF1BytesGenerator.init(new MGFParameters(obj2));
        mGF1BytesGenerator.generateBytes(bArr2, 0, bArr2.length);
        System.arraycopy(obj2, 0, obj, 0, obj2.length);
        System.arraycopy(bArr, 0, obj, obj2.length, bArr.length);
        for (length = (obj2.length + bArr.length) + 1; length != obj.length; length++) {
            obj[length] = (byte) (this.random.nextInt(255) + 1);
        }
        for (length = 0; length != bArr2.length; length++) {
            int length2 = obj2.length + length;
            obj[length2] = (byte) (obj[length2] ^ bArr2[length]);
        }
        return obj;
    }

    public byte[] getUnpaddedData(byte[] bArr) {
        int i;
        Object obj = new byte[this.dig.getDigestSize()];
        byte[] bArr2 = new byte[(this.length - this.dig.getDigestSize())];
        System.arraycopy(bArr, 0, obj, 0, obj.length);
        MGF1BytesGenerator mGF1BytesGenerator = new MGF1BytesGenerator(this.dig);
        mGF1BytesGenerator.init(new MGFParameters(obj));
        mGF1BytesGenerator.generateBytes(bArr2, 0, bArr2.length);
        for (i = 0; i != bArr2.length; i++) {
            int length = obj.length + i;
            bArr[length] = (byte) (bArr[length] ^ bArr2[i]);
        }
        i = bArr.length - 1;
        while (i != obj.length) {
            if (bArr[i] == (byte) 0) {
                break;
            }
            i--;
        }
        i = 0;
        if (i == 0) {
            throw new IllegalStateException("bad padding in encoding");
        }
        Object obj2 = new byte[(i - obj.length)];
        System.arraycopy(bArr, obj.length, obj2, 0, obj2.length);
        return obj2;
    }
}
