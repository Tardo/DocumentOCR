package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class VMPCEngine implements StreamCipher {
    /* renamed from: P */
    protected byte[] f249P = null;
    /* renamed from: n */
    protected byte f250n = (byte) 0;
    /* renamed from: s */
    protected byte f251s = (byte) 0;
    protected byte[] workingIV;
    protected byte[] workingKey;

    public String getAlgorithmName() {
        return "VMPC";
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            KeyParameter keyParameter = (KeyParameter) parametersWithIV.getParameters();
            if (parametersWithIV.getParameters() instanceof KeyParameter) {
                this.workingIV = parametersWithIV.getIV();
                if (this.workingIV == null || this.workingIV.length < 1 || this.workingIV.length > 768) {
                    throw new IllegalArgumentException("VMPC requires 1 to 768 bytes of IV");
                }
                this.workingKey = keyParameter.getKey();
                initKey(this.workingKey, this.workingIV);
                return;
            }
            throw new IllegalArgumentException("VMPC init parameters must include a key");
        }
        throw new IllegalArgumentException("VMPC init parameters must include an IV");
    }

    protected void initKey(byte[] bArr, byte[] bArr2) {
        int i;
        this.f251s = (byte) 0;
        this.f249P = new byte[256];
        for (i = 0; i < 256; i++) {
            this.f249P[i] = (byte) i;
        }
        for (i = 0; i < 768; i++) {
            this.f251s = this.f249P[((this.f251s + this.f249P[i & 255]) + bArr[i % bArr.length]) & 255];
            byte b = this.f249P[i & 255];
            this.f249P[i & 255] = this.f249P[this.f251s & 255];
            this.f249P[this.f251s & 255] = b;
        }
        for (i = 0; i < 768; i++) {
            this.f251s = this.f249P[((this.f251s + this.f249P[i & 255]) + bArr2[i % bArr2.length]) & 255];
            b = this.f249P[i & 255];
            this.f249P[i & 255] = this.f249P[this.f251s & 255];
            this.f249P[this.f251s & 255] = b;
        }
        this.f250n = (byte) 0;
    }

    public void processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        } else if (i3 + i2 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            for (int i4 = 0; i4 < i2; i4++) {
                this.f251s = this.f249P[(this.f251s + this.f249P[this.f250n & 255]) & 255];
                byte b = this.f249P[(this.f249P[this.f249P[this.f251s & 255] & 255] + 1) & 255];
                byte b2 = this.f249P[this.f250n & 255];
                this.f249P[this.f250n & 255] = this.f249P[this.f251s & 255];
                this.f249P[this.f251s & 255] = b2;
                this.f250n = (byte) ((this.f250n + 1) & 255);
                bArr2[i4 + i3] = (byte) (b ^ bArr[i4 + i]);
            }
        }
    }

    public void reset() {
        initKey(this.workingKey, this.workingIV);
    }

    public byte returnByte(byte b) {
        this.f251s = this.f249P[(this.f251s + this.f249P[this.f250n & 255]) & 255];
        byte b2 = this.f249P[(this.f249P[this.f249P[this.f251s & 255] & 255] + 1) & 255];
        byte b3 = this.f249P[this.f250n & 255];
        this.f249P[this.f250n & 255] = this.f249P[this.f251s & 255];
        this.f249P[this.f251s & 255] = b3;
        this.f250n = (byte) ((this.f250n + 1) & 255);
        return (byte) (b2 ^ b);
    }
}
