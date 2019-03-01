package org.bouncycastle.pqc.crypto.gmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class GMSSLeaf {
    private byte[] concHashs;
    private GMSSRandom gmssRandom;
    /* renamed from: i */
    private int f119i;
    /* renamed from: j */
    private int f120j;
    private int keysize;
    private byte[] leaf;
    private int mdsize;
    private Digest messDigestOTS;
    byte[] privateKeyOTS;
    private byte[] seed;
    private int steps;
    private int two_power_w;
    /* renamed from: w */
    private int f121w;

    GMSSLeaf(Digest digest, int i, int i2) {
        this.f121w = i;
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        int ceil = (int) Math.ceil(((double) (this.mdsize << 3)) / ((double) i));
        this.keysize = ceil + ((int) Math.ceil(((double) getLog((ceil << i) + 1)) / ((double) i)));
        this.two_power_w = 1 << i;
        this.steps = (int) Math.ceil(((double) (((((1 << i) - 1) * this.keysize) + 1) + this.keysize)) / ((double) i2));
        this.seed = new byte[this.mdsize];
        this.leaf = new byte[this.mdsize];
        this.privateKeyOTS = new byte[this.mdsize];
        this.concHashs = new byte[(this.mdsize * this.keysize)];
    }

    public GMSSLeaf(Digest digest, int i, int i2, byte[] bArr) {
        this.f121w = i;
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        int ceil = (int) Math.ceil(((double) (this.mdsize << 3)) / ((double) i));
        this.keysize = ceil + ((int) Math.ceil(((double) getLog((ceil << i) + 1)) / ((double) i)));
        this.two_power_w = 1 << i;
        this.steps = (int) Math.ceil(((double) (((((1 << i) - 1) * this.keysize) + 1) + this.keysize)) / ((double) i2));
        this.seed = new byte[this.mdsize];
        this.leaf = new byte[this.mdsize];
        this.privateKeyOTS = new byte[this.mdsize];
        this.concHashs = new byte[(this.mdsize * this.keysize)];
        initLeafCalc(bArr);
    }

    public GMSSLeaf(Digest digest, byte[][] bArr, int[] iArr) {
        this.f119i = iArr[0];
        this.f120j = iArr[1];
        this.steps = iArr[2];
        this.f121w = iArr[3];
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        int ceil = (int) Math.ceil(((double) (this.mdsize << 3)) / ((double) this.f121w));
        this.keysize = ceil + ((int) Math.ceil(((double) getLog((ceil << this.f121w) + 1)) / ((double) this.f121w)));
        this.two_power_w = 1 << this.f121w;
        this.privateKeyOTS = bArr[0];
        this.seed = bArr[1];
        this.concHashs = bArr[2];
        this.leaf = bArr[3];
    }

    private GMSSLeaf(GMSSLeaf gMSSLeaf) {
        this.messDigestOTS = gMSSLeaf.messDigestOTS;
        this.mdsize = gMSSLeaf.mdsize;
        this.keysize = gMSSLeaf.keysize;
        this.gmssRandom = gMSSLeaf.gmssRandom;
        this.leaf = Arrays.clone(gMSSLeaf.leaf);
        this.concHashs = Arrays.clone(gMSSLeaf.concHashs);
        this.f119i = gMSSLeaf.f119i;
        this.f120j = gMSSLeaf.f120j;
        this.two_power_w = gMSSLeaf.two_power_w;
        this.f121w = gMSSLeaf.f121w;
        this.steps = gMSSLeaf.steps;
        this.seed = Arrays.clone(gMSSLeaf.seed);
        this.privateKeyOTS = Arrays.clone(gMSSLeaf.privateKeyOTS);
    }

    private int getLog(int i) {
        int i2 = 1;
        int i3 = 2;
        while (i3 < i) {
            i3 <<= 1;
            i2++;
        }
        return i2;
    }

    private void updateLeafCalc() {
        byte[] bArr = new byte[this.messDigestOTS.getDigestSize()];
        for (int i = 0; i < this.steps + 10000; i++) {
            if (this.f119i == this.keysize && this.f120j == this.two_power_w - 1) {
                this.messDigestOTS.update(this.concHashs, 0, this.concHashs.length);
                this.leaf = new byte[this.messDigestOTS.getDigestSize()];
                this.messDigestOTS.doFinal(this.leaf, 0);
                return;
            }
            if (this.f119i == 0 || this.f120j == this.two_power_w - 1) {
                this.f119i++;
                this.f120j = 0;
                this.privateKeyOTS = this.gmssRandom.nextSeed(this.seed);
            } else {
                this.messDigestOTS.update(this.privateKeyOTS, 0, this.privateKeyOTS.length);
                this.privateKeyOTS = bArr;
                this.messDigestOTS.doFinal(this.privateKeyOTS, 0);
                this.f120j++;
                if (this.f120j == this.two_power_w - 1) {
                    System.arraycopy(this.privateKeyOTS, 0, this.concHashs, this.mdsize * (this.f119i - 1), this.mdsize);
                }
            }
        }
        throw new IllegalStateException("unable to updateLeaf in steps: " + this.steps + " " + this.f119i + " " + this.f120j);
    }

    public byte[] getLeaf() {
        return Arrays.clone(this.leaf);
    }

    public byte[][] getStatByte() {
        byte[][] bArr = new byte[][]{new byte[this.mdsize], new byte[this.mdsize], new byte[(this.mdsize * this.keysize)], new byte[this.mdsize]};
        bArr[0] = this.privateKeyOTS;
        bArr[1] = this.seed;
        bArr[2] = this.concHashs;
        bArr[3] = this.leaf;
        return bArr;
    }

    public int[] getStatInt() {
        return new int[]{this.f119i, this.f120j, this.steps, this.f121w};
    }

    void initLeafCalc(byte[] bArr) {
        this.f119i = 0;
        this.f120j = 0;
        Object obj = new byte[this.mdsize];
        System.arraycopy(bArr, 0, obj, 0, this.seed.length);
        this.seed = this.gmssRandom.nextSeed(obj);
    }

    GMSSLeaf nextLeaf() {
        GMSSLeaf gMSSLeaf = new GMSSLeaf(this);
        gMSSLeaf.updateLeafCalc();
        return gMSSLeaf;
    }

    public String toString() {
        int i;
        String str = "";
        for (i = 0; i < 4; i++) {
            str = str + getStatInt()[i] + " ";
        }
        String str2 = str + " " + this.mdsize + " " + this.keysize + " " + this.two_power_w + " ";
        byte[][] statByte = getStatByte();
        String str3 = str2;
        for (i = 0; i < 4; i++) {
            str3 = statByte[i] != null ? str3 + new String(Hex.encode(statByte[i])) + " " : str3 + "null ";
        }
        return str3;
    }
}
