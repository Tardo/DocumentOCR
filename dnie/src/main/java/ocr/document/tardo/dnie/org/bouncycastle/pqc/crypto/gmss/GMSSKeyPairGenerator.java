package org.bouncycastle.pqc.crypto.gmss;

import java.lang.reflect.Array;
import java.security.SecureRandom;
import java.util.Vector;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSVerify;
import org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSignature;

public class GMSSKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.3";
    /* renamed from: K */
    private int[] f309K;
    private byte[][] currentRootSigs;
    private byte[][] currentSeeds;
    private GMSSDigestProvider digestProvider;
    private GMSSParameters gmssPS;
    private GMSSKeyGenerationParameters gmssParams;
    private GMSSRandom gmssRandom;
    private int[] heightOfTrees;
    private boolean initialized = false;
    private int mdLength;
    private Digest messDigestTree;
    private byte[][] nextNextSeeds;
    private int numLayer;
    private int[] otsIndex;

    public GMSSKeyPairGenerator(GMSSDigestProvider gMSSDigestProvider) {
        this.digestProvider = gMSSDigestProvider;
        this.messDigestTree = gMSSDigestProvider.get();
        this.mdLength = this.messDigestTree.getDigestSize();
        this.gmssRandom = new GMSSRandom(this.messDigestTree);
    }

    private AsymmetricCipherKeyPair genKeyPair() {
        int i;
        if (!this.initialized) {
            initializeDefault();
        }
        byte[][][] bArr = new byte[this.numLayer][][];
        byte[][][] bArr2 = new byte[(this.numLayer - 1)][][];
        Treehash[][] treehashArr = new Treehash[this.numLayer][];
        Treehash[][] treehashArr2 = new Treehash[(this.numLayer - 1)][];
        Vector[] vectorArr = new Vector[this.numLayer];
        Vector[] vectorArr2 = new Vector[(this.numLayer - 1)];
        Vector[][] vectorArr3 = new Vector[this.numLayer][];
        Vector[][] vectorArr4 = new Vector[(this.numLayer - 1)][];
        for (int i2 = 0; i2 < this.numLayer; i2++) {
            bArr[i2] = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{this.heightOfTrees[i2], this.mdLength});
            treehashArr[i2] = new Treehash[(this.heightOfTrees[i2] - this.f309K[i2])];
            if (i2 > 0) {
                bArr2[i2 - 1] = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{this.heightOfTrees[i2], this.mdLength});
                treehashArr2[i2 - 1] = new Treehash[(this.heightOfTrees[i2] - this.f309K[i2])];
            }
            vectorArr[i2] = new Vector();
            if (i2 > 0) {
                vectorArr2[i2 - 1] = new Vector();
            }
        }
        byte[][] bArr3 = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{this.numLayer, this.mdLength});
        byte[][] bArr4 = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{this.numLayer - 1, this.mdLength});
        byte[][] bArr5 = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{this.numLayer, this.mdLength});
        for (i = 0; i < this.numLayer; i++) {
            System.arraycopy(this.currentSeeds[i], 0, bArr5[i], 0, this.mdLength);
        }
        this.currentRootSigs = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{this.numLayer - 1, this.mdLength});
        for (int i3 = this.numLayer - 1; i3 >= 0; i3--) {
            int i4;
            GMSSRootCalc gMSSRootCalc = new GMSSRootCalc(this.heightOfTrees[i3], this.f309K[i3], this.digestProvider);
            try {
                if (i3 == this.numLayer - 1) {
                    gMSSRootCalc = generateCurrentAuthpathAndRoot(null, vectorArr[i3], bArr5[i3], i3);
                } else {
                    gMSSRootCalc = generateCurrentAuthpathAndRoot(bArr3[i3 + 1], vectorArr[i3], bArr5[i3], i3);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            for (i4 = 0; i4 < this.heightOfTrees[i3]; i4++) {
                System.arraycopy(gMSSRootCalc.getAuthPath()[i4], 0, bArr[i3][i4], 0, this.mdLength);
            }
            vectorArr3[i3] = gMSSRootCalc.getRetain();
            treehashArr[i3] = gMSSRootCalc.getTreehash();
            System.arraycopy(gMSSRootCalc.getRoot(), 0, bArr3[i3], 0, this.mdLength);
        }
        for (i4 = this.numLayer - 2; i4 >= 0; i4--) {
            GMSSRootCalc generateNextAuthpathAndRoot = generateNextAuthpathAndRoot(vectorArr2[i4], bArr5[i4 + 1], i4 + 1);
            for (i = 0; i < this.heightOfTrees[i4 + 1]; i++) {
                System.arraycopy(generateNextAuthpathAndRoot.getAuthPath()[i], 0, bArr2[i4][i], 0, this.mdLength);
            }
            vectorArr4[i4] = generateNextAuthpathAndRoot.getRetain();
            treehashArr2[i4] = generateNextAuthpathAndRoot.getTreehash();
            System.arraycopy(generateNextAuthpathAndRoot.getRoot(), 0, bArr4[i4], 0, this.mdLength);
            System.arraycopy(bArr5[i4 + 1], 0, this.nextNextSeeds[i4], 0, this.mdLength);
        }
        return new AsymmetricCipherKeyPair(new GMSSPublicKeyParameters(bArr3[0], this.gmssPS), new GMSSPrivateKeyParameters(this.currentSeeds, this.nextNextSeeds, bArr, bArr2, treehashArr, treehashArr2, vectorArr, vectorArr2, vectorArr3, vectorArr4, bArr4, this.currentRootSigs, this.gmssPS, this.digestProvider));
    }

    private GMSSRootCalc generateCurrentAuthpathAndRoot(byte[] bArr, Vector vector, byte[] bArr2, int i) {
        byte[] bArr3 = new byte[this.mdLength];
        bArr3 = new byte[this.mdLength];
        bArr3 = this.gmssRandom.nextSeed(bArr2);
        GMSSRootCalc gMSSRootCalc = new GMSSRootCalc(this.heightOfTrees[i], this.f309K[i], this.digestProvider);
        gMSSRootCalc.initialize(vector);
        if (i == this.numLayer - 1) {
            bArr3 = new WinternitzOTSignature(bArr3, this.digestProvider.get(), this.otsIndex[i]).getPublicKey();
        } else {
            this.currentRootSigs[i] = new WinternitzOTSignature(bArr3, this.digestProvider.get(), this.otsIndex[i]).getSignature(bArr);
            bArr3 = new WinternitzOTSVerify(this.digestProvider.get(), this.otsIndex[i]).Verify(bArr, this.currentRootSigs[i]);
        }
        gMSSRootCalc.update(bArr3);
        int i2 = 3;
        int i3 = 0;
        for (int i4 = 1; i4 < (1 << this.heightOfTrees[i]); i4++) {
            if (i4 == i2 && i3 < this.heightOfTrees[i] - this.f309K[i]) {
                gMSSRootCalc.initializeTreehashSeed(bArr2, i3);
                i2 *= 2;
                i3++;
            }
            gMSSRootCalc.update(new WinternitzOTSignature(this.gmssRandom.nextSeed(bArr2), this.digestProvider.get(), this.otsIndex[i]).getPublicKey());
        }
        if (gMSSRootCalc.wasFinished()) {
            return gMSSRootCalc;
        }
        System.err.println("Baum noch nicht fertig konstruiert!!!");
        return null;
    }

    private GMSSRootCalc generateNextAuthpathAndRoot(Vector vector, byte[] bArr, int i) {
        int i2 = 0;
        byte[] bArr2 = new byte[this.numLayer];
        GMSSRootCalc gMSSRootCalc = new GMSSRootCalc(this.heightOfTrees[i], this.f309K[i], this.digestProvider);
        gMSSRootCalc.initialize(vector);
        int i3 = 3;
        int i4 = 0;
        while (i2 < (1 << this.heightOfTrees[i])) {
            if (i2 == i3 && i4 < this.heightOfTrees[i] - this.f309K[i]) {
                gMSSRootCalc.initializeTreehashSeed(bArr, i4);
                i3 *= 2;
                i4++;
            }
            gMSSRootCalc.update(new WinternitzOTSignature(this.gmssRandom.nextSeed(bArr), this.digestProvider.get(), this.otsIndex[i]).getPublicKey());
            i2++;
        }
        if (gMSSRootCalc.wasFinished()) {
            return gMSSRootCalc;
        }
        System.err.println("N�chster Baum noch nicht fertig konstruiert!!!");
        return null;
    }

    private void initializeDefault() {
        int[] iArr = new int[]{10, 10, 10, 10};
        initialize(new GMSSKeyGenerationParameters(new SecureRandom(), new GMSSParameters(iArr.length, iArr, new int[]{3, 3, 3, 3}, new int[]{2, 2, 2, 2})));
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        return genKeyPair();
    }

    public void init(KeyGenerationParameters keyGenerationParameters) {
        initialize(keyGenerationParameters);
    }

    public void initialize(int i, SecureRandom secureRandom) {
        KeyGenerationParameters gMSSKeyGenerationParameters;
        int[] iArr;
        if (i <= 10) {
            iArr = new int[]{10};
            gMSSKeyGenerationParameters = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(iArr.length, iArr, new int[]{3}, new int[]{2}));
        } else if (i <= 20) {
            iArr = new int[]{10, 10};
            gMSSKeyGenerationParameters = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(iArr.length, iArr, new int[]{5, 4}, new int[]{2, 2}));
        } else {
            iArr = new int[]{10, 10, 10, 10};
            gMSSKeyGenerationParameters = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(iArr.length, iArr, new int[]{9, 9, 9, 3}, new int[]{2, 2, 2, 2}));
        }
        initialize(gMSSKeyGenerationParameters);
    }

    public void initialize(KeyGenerationParameters keyGenerationParameters) {
        this.gmssParams = (GMSSKeyGenerationParameters) keyGenerationParameters;
        this.gmssPS = new GMSSParameters(this.gmssParams.getParameters().getNumOfLayers(), this.gmssParams.getParameters().getHeightOfTrees(), this.gmssParams.getParameters().getWinternitzParameter(), this.gmssParams.getParameters().getK());
        this.numLayer = this.gmssPS.getNumOfLayers();
        this.heightOfTrees = this.gmssPS.getHeightOfTrees();
        this.otsIndex = this.gmssPS.getWinternitzParameter();
        this.f309K = this.gmssPS.getK();
        this.currentSeeds = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{this.numLayer, this.mdLength});
        this.nextNextSeeds = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{this.numLayer - 1, this.mdLength});
        SecureRandom secureRandom = new SecureRandom();
        for (int i = 0; i < this.numLayer; i++) {
            secureRandom.nextBytes(this.currentSeeds[i]);
            this.gmssRandom.nextSeed(this.currentSeeds[i]);
        }
        this.initialized = true;
    }
}
