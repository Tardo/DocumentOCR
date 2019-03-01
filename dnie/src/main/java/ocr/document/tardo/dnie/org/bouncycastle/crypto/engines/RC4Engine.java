package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class RC4Engine implements StreamCipher {
    private static final int STATE_LENGTH = 256;
    private byte[] engineState = null;
    private byte[] workingKey = null;
    /* renamed from: x */
    private int f244x = 0;
    /* renamed from: y */
    private int f245y = 0;

    private void setKey(byte[] bArr) {
        int i;
        int i2 = 0;
        this.workingKey = bArr;
        this.f244x = 0;
        this.f245y = 0;
        if (this.engineState == null) {
            this.engineState = new byte[256];
        }
        for (i = 0; i < 256; i++) {
            this.engineState[i] = (byte) i;
        }
        i = 0;
        int i3 = 0;
        while (i2 < 256) {
            i = (i + ((bArr[i3] & 255) + this.engineState[i2])) & 255;
            byte b = this.engineState[i2];
            this.engineState[i2] = this.engineState[i];
            this.engineState[i] = b;
            i3 = (i3 + 1) % bArr.length;
            i2++;
        }
    }

    public String getAlgorithmName() {
        return "RC4";
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        if (cipherParameters instanceof KeyParameter) {
            this.workingKey = ((KeyParameter) cipherParameters).getKey();
            setKey(this.workingKey);
            return;
        }
        throw new IllegalArgumentException("invalid parameter passed to RC4 init - " + cipherParameters.getClass().getName());
    }

    public void processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        } else if (i3 + i2 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            for (int i4 = 0; i4 < i2; i4++) {
                this.f244x = (this.f244x + 1) & 255;
                this.f245y = (this.engineState[this.f244x] + this.f245y) & 255;
                byte b = this.engineState[this.f244x];
                this.engineState[this.f244x] = this.engineState[this.f245y];
                this.engineState[this.f245y] = b;
                bArr2[i4 + i3] = (byte) (bArr[i4 + i] ^ this.engineState[(this.engineState[this.f244x] + this.engineState[this.f245y]) & 255]);
            }
        }
    }

    public void reset() {
        setKey(this.workingKey);
    }

    public byte returnByte(byte b) {
        this.f244x = (this.f244x + 1) & 255;
        this.f245y = (this.engineState[this.f244x] + this.f245y) & 255;
        byte b2 = this.engineState[this.f244x];
        this.engineState[this.f244x] = this.engineState[this.f245y];
        this.engineState[this.f245y] = b2;
        return (byte) (this.engineState[(this.engineState[this.f244x] + this.engineState[this.f245y]) & 255] ^ b);
    }
}
