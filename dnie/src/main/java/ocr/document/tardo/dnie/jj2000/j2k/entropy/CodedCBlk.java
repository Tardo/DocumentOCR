package jj2000.j2k.entropy;

public class CodedCBlk {
    public byte[] data;
    /* renamed from: m */
    public int f30m;
    /* renamed from: n */
    public int f31n;
    public int skipMSBP;

    public CodedCBlk(int m, int n, int skipMSBP, byte[] data) {
        this.f30m = m;
        this.f31n = n;
        this.skipMSBP = skipMSBP;
        this.data = data;
    }

    public String toString() {
        return "m=" + this.f30m + ", n=" + this.f31n + ", skipMSBP=" + this.skipMSBP + ", data.length=" + (this.data != null ? "" + this.data.length : "(null)");
    }
}
