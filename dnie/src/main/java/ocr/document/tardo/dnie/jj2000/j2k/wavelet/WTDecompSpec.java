package jj2000.j2k.wavelet;

import jj2000.j2k.NotImplementedError;

public class WTDecompSpec {
    public static final byte DEC_SPEC_COMP_DEF = (byte) 1;
    public static final byte DEC_SPEC_MAIN_DEF = (byte) 0;
    public static final byte DEC_SPEC_TILE_COMP = (byte) 3;
    public static final byte DEC_SPEC_TILE_DEF = (byte) 2;
    public static final int WT_DECOMP_DYADIC = 0;
    public static final int WT_DECOMP_PACKET = 1;
    public static final int WT_DECOMP_SPACL = 2;
    private int[] compMainDefDecompType;
    private int[] compMainDefLevels;
    private int mainDefDecompType;
    private int mainDefLevels;
    private byte[] specValType;

    public WTDecompSpec(int nc, int dec, int lev) {
        this.mainDefDecompType = dec;
        this.mainDefLevels = lev;
        this.specValType = new byte[nc];
    }

    public void setMainCompDefDecompType(int n, int dec, int lev) {
        if (dec >= 0 || lev >= 0) {
            this.specValType[n] = (byte) 1;
            if (this.compMainDefDecompType == null) {
                this.compMainDefDecompType = new int[this.specValType.length];
                this.compMainDefLevels = new int[this.specValType.length];
            }
            int[] iArr = this.compMainDefDecompType;
            if (dec < 0) {
                dec = this.mainDefDecompType;
            }
            iArr[n] = dec;
            iArr = this.compMainDefLevels;
            if (lev < 0) {
                lev = this.mainDefLevels;
            }
            iArr[n] = lev;
            throw new NotImplementedError("Currently, in JJ2000, all components and tiles must have the same decomposition type and number of levels");
        }
        throw new IllegalArgumentException();
    }

    public byte getDecSpecType(int n) {
        return this.specValType[n];
    }

    public int getMainDefDecompType() {
        return this.mainDefDecompType;
    }

    public int getMainDefLevels() {
        return this.mainDefLevels;
    }

    public int getDecompType(int n) {
        switch (this.specValType[n]) {
            case (byte) 0:
                return this.mainDefDecompType;
            case (byte) 1:
                return this.compMainDefDecompType[n];
            case (byte) 2:
                throw new NotImplementedError();
            case (byte) 3:
                throw new NotImplementedError();
            default:
                throw new Error("Internal JJ2000 error");
        }
    }

    public int getLevels(int n) {
        switch (this.specValType[n]) {
            case (byte) 0:
                return this.mainDefLevels;
            case (byte) 1:
                return this.compMainDefLevels[n];
            case (byte) 2:
                throw new NotImplementedError();
            case (byte) 3:
                throw new NotImplementedError();
            default:
                throw new Error("Internal JJ2000 error");
        }
    }
}
