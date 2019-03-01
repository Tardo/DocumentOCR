package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class VMPCMac implements Mac {
    /* renamed from: P */
    private byte[] f258P = null;
    /* renamed from: T */
    private byte[] f259T;
    /* renamed from: g */
    private byte f260g;
    /* renamed from: n */
    private byte f261n = (byte) 0;
    /* renamed from: s */
    private byte f262s = (byte) 0;
    private byte[] workingIV;
    private byte[] workingKey;
    private byte x1;
    private byte x2;
    private byte x3;
    private byte x4;

    private void initKey(byte[] bArr, byte[] bArr2) {
        int i;
        this.f262s = (byte) 0;
        this.f258P = new byte[256];
        for (i = 0; i < 256; i++) {
            this.f258P[i] = (byte) i;
        }
        for (i = 0; i < 768; i++) {
            this.f262s = this.f258P[((this.f262s + this.f258P[i & 255]) + bArr[i % bArr.length]) & 255];
            byte b = this.f258P[i & 255];
            this.f258P[i & 255] = this.f258P[this.f262s & 255];
            this.f258P[this.f262s & 255] = b;
        }
        for (i = 0; i < 768; i++) {
            this.f262s = this.f258P[((this.f262s + this.f258P[i & 255]) + bArr2[i % bArr2.length]) & 255];
            b = this.f258P[i & 255];
            this.f258P[i & 255] = this.f258P[this.f262s & 255];
            this.f258P[this.f262s & 255] = b;
        }
        this.f261n = (byte) 0;
    }

    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        int i2;
        for (i2 = 1; i2 < 25; i2++) {
            this.f262s = this.f258P[(this.f262s + this.f258P[this.f261n & 255]) & 255];
            this.x4 = this.f258P[((this.x4 + this.x3) + i2) & 255];
            this.x3 = this.f258P[((this.x3 + this.x2) + i2) & 255];
            this.x2 = this.f258P[((this.x2 + this.x1) + i2) & 255];
            this.x1 = this.f258P[((this.x1 + this.f262s) + i2) & 255];
            this.f259T[this.f260g & 31] = (byte) (this.f259T[this.f260g & 31] ^ this.x1);
            this.f259T[(this.f260g + 1) & 31] = (byte) (this.f259T[(this.f260g + 1) & 31] ^ this.x2);
            this.f259T[(this.f260g + 2) & 31] = (byte) (this.f259T[(this.f260g + 2) & 31] ^ this.x3);
            this.f259T[(this.f260g + 3) & 31] = (byte) (this.f259T[(this.f260g + 3) & 31] ^ this.x4);
            this.f260g = (byte) ((this.f260g + 4) & 31);
            byte b = this.f258P[this.f261n & 255];
            this.f258P[this.f261n & 255] = this.f258P[this.f262s & 255];
            this.f258P[this.f262s & 255] = b;
            this.f261n = (byte) ((this.f261n + 1) & 255);
        }
        for (i2 = 0; i2 < 768; i2++) {
            this.f262s = this.f258P[((this.f262s + this.f258P[i2 & 255]) + this.f259T[i2 & 31]) & 255];
            b = this.f258P[i2 & 255];
            this.f258P[i2 & 255] = this.f258P[this.f262s & 255];
            this.f258P[this.f262s & 255] = b;
        }
        Object obj = new byte[20];
        for (i2 = 0; i2 < 20; i2++) {
            this.f262s = this.f258P[(this.f262s + this.f258P[i2 & 255]) & 255];
            obj[i2] = this.f258P[(this.f258P[this.f258P[this.f262s & 255] & 255] + 1) & 255];
            byte b2 = this.f258P[i2 & 255];
            this.f258P[i2 & 255] = this.f258P[this.f262s & 255];
            this.f258P[this.f262s & 255] = b2;
        }
        System.arraycopy(obj, 0, bArr, i, obj.length);
        reset();
        return obj.length;
    }

    public String getAlgorithmName() {
        return "VMPC-MAC";
    }

    public int getMacSize() {
        return 20;
    }

    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            KeyParameter keyParameter = (KeyParameter) parametersWithIV.getParameters();
            if (parametersWithIV.getParameters() instanceof KeyParameter) {
                this.workingIV = parametersWithIV.getIV();
                if (this.workingIV == null || this.workingIV.length < 1 || this.workingIV.length > 768) {
                    throw new IllegalArgumentException("VMPC-MAC requires 1 to 768 bytes of IV");
                }
                this.workingKey = keyParameter.getKey();
                reset();
                return;
            }
            throw new IllegalArgumentException("VMPC-MAC Init parameters must include a key");
        }
        throw new IllegalArgumentException("VMPC-MAC Init parameters must include an IV");
    }

    public void reset() {
        initKey(this.workingKey, this.workingIV);
        this.f261n = (byte) 0;
        this.x4 = (byte) 0;
        this.x3 = (byte) 0;
        this.x2 = (byte) 0;
        this.x1 = (byte) 0;
        this.f260g = (byte) 0;
        this.f259T = new byte[32];
        for (int i = 0; i < 32; i++) {
            this.f259T[i] = (byte) 0;
        }
    }

    public void update(byte b) throws IllegalStateException {
        this.f262s = this.f258P[(this.f262s + this.f258P[this.f261n & 255]) & 255];
        byte b2 = (byte) (this.f258P[(this.f258P[this.f258P[this.f262s & 255] & 255] + 1) & 255] ^ b);
        this.x4 = this.f258P[(this.x4 + this.x3) & 255];
        this.x3 = this.f258P[(this.x3 + this.x2) & 255];
        this.x2 = this.f258P[(this.x2 + this.x1) & 255];
        this.x1 = this.f258P[(b2 + (this.x1 + this.f262s)) & 255];
        this.f259T[this.f260g & 31] = (byte) (this.f259T[this.f260g & 31] ^ this.x1);
        this.f259T[(this.f260g + 1) & 31] = (byte) (this.f259T[(this.f260g + 1) & 31] ^ this.x2);
        this.f259T[(this.f260g + 2) & 31] = (byte) (this.f259T[(this.f260g + 2) & 31] ^ this.x3);
        this.f259T[(this.f260g + 3) & 31] = (byte) (this.f259T[(this.f260g + 3) & 31] ^ this.x4);
        this.f260g = (byte) ((this.f260g + 4) & 31);
        b2 = this.f258P[this.f261n & 255];
        this.f258P[this.f261n & 255] = this.f258P[this.f262s & 255];
        this.f258P[this.f262s & 255] = b2;
        this.f261n = (byte) ((this.f261n + 1) & 255);
    }

    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        for (int i3 = 0; i3 < i2; i3++) {
            update(bArr[i3]);
        }
    }
}
