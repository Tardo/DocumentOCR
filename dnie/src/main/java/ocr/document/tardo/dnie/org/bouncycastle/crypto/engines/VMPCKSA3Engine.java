package org.bouncycastle.crypto.engines;

public class VMPCKSA3Engine extends VMPCEngine {
    public String getAlgorithmName() {
        return "VMPC-KSA3";
    }

    protected void initKey(byte[] bArr, byte[] bArr2) {
        int i;
        this.s = (byte) 0;
        this.P = new byte[256];
        for (i = 0; i < 256; i++) {
            this.P[i] = (byte) i;
        }
        for (i = 0; i < 768; i++) {
            this.s = this.P[((this.s + this.P[i & 255]) + bArr[i % bArr.length]) & 255];
            byte b = this.P[i & 255];
            this.P[i & 255] = this.P[this.s & 255];
            this.P[this.s & 255] = b;
        }
        for (i = 0; i < 768; i++) {
            this.s = this.P[((this.s + this.P[i & 255]) + bArr2[i % bArr2.length]) & 255];
            b = this.P[i & 255];
            this.P[i & 255] = this.P[this.s & 255];
            this.P[this.s & 255] = b;
        }
        for (i = 0; i < 768; i++) {
            this.s = this.P[((this.s + this.P[i & 255]) + bArr[i % bArr.length]) & 255];
            b = this.P[i & 255];
            this.P[i & 255] = this.P[this.s & 255];
            this.P[this.s & 255] = b;
        }
        this.n = (byte) 0;
    }
}
