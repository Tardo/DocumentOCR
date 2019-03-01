package jj2000.j2k.wavelet;

import jj2000.j2k.image.Coord;

public abstract class Subband {
    public static final int WT_ORIENT_HH = 3;
    public static final int WT_ORIENT_HL = 1;
    public static final int WT_ORIENT_LH = 2;
    public static final int WT_ORIENT_LL = 0;
    public int anGainExp;
    /* renamed from: h */
    public int f42h;
    public boolean isNode;
    public int level;
    public int nomCBlkH;
    public int nomCBlkW;
    public Coord numCb = null;
    public int orientation;
    public int resLvl;
    public int sbandIdx = 0;
    public int ulcx;
    public int ulcy;
    public int ulx;
    public int uly;
    /* renamed from: w */
    public int f43w;

    public abstract Subband getHH();

    public abstract Subband getHL();

    public abstract WaveletFilter getHorWFilter();

    public abstract Subband getLH();

    public abstract Subband getLL();

    public abstract Subband getParent();

    public abstract WaveletFilter getVerWFilter();

    protected abstract Subband split(WaveletFilter waveletFilter, WaveletFilter waveletFilter2);

    protected void initChilds() {
        Subband subb_LL = getLL();
        Subband subb_HL = getHL();
        Subband subb_LH = getLH();
        Subband subb_HH = getHH();
        subb_LL.level = this.level + 1;
        subb_LL.ulcx = (this.ulcx + 1) >> 1;
        subb_LL.ulcy = (this.ulcy + 1) >> 1;
        subb_LL.ulx = this.ulx;
        subb_LL.uly = this.uly;
        subb_LL.f43w = (((this.ulcx + this.f43w) + 1) >> 1) - subb_LL.ulcx;
        subb_LL.f42h = (((this.ulcy + this.f42h) + 1) >> 1) - subb_LL.ulcy;
        subb_LL.resLvl = this.orientation == 0 ? this.resLvl - 1 : this.resLvl;
        subb_LL.anGainExp = this.anGainExp;
        subb_LL.sbandIdx = this.sbandIdx << 2;
        subb_HL.orientation = 1;
        subb_HL.level = subb_LL.level;
        subb_HL.ulcx = this.ulcx >> 1;
        subb_HL.ulcy = subb_LL.ulcy;
        subb_HL.ulx = this.ulx + subb_LL.f43w;
        subb_HL.uly = this.uly;
        subb_HL.f43w = ((this.ulcx + this.f43w) >> 1) - subb_HL.ulcx;
        subb_HL.f42h = subb_LL.f42h;
        subb_HL.resLvl = this.resLvl;
        subb_HL.anGainExp = this.anGainExp + 1;
        subb_HL.sbandIdx = (this.sbandIdx << 2) + 1;
        subb_LH.orientation = 2;
        subb_LH.level = subb_LL.level;
        subb_LH.ulcx = subb_LL.ulcx;
        subb_LH.ulcy = this.ulcy >> 1;
        subb_LH.ulx = this.ulx;
        subb_LH.uly = this.uly + subb_LL.f42h;
        subb_LH.f43w = subb_LL.f43w;
        subb_LH.f42h = ((this.ulcy + this.f42h) >> 1) - subb_LH.ulcy;
        subb_LH.resLvl = this.resLvl;
        subb_LH.anGainExp = this.anGainExp + 1;
        subb_LH.sbandIdx = (this.sbandIdx << 2) + 2;
        subb_HH.orientation = 3;
        subb_HH.level = subb_LL.level;
        subb_HH.ulcx = subb_HL.ulcx;
        subb_HH.ulcy = subb_LH.ulcy;
        subb_HH.ulx = subb_HL.ulx;
        subb_HH.uly = subb_LH.uly;
        subb_HH.f43w = subb_HL.f43w;
        subb_HH.f42h = subb_LH.f42h;
        subb_HH.resLvl = this.resLvl;
        subb_HH.anGainExp = this.anGainExp + 2;
        subb_HH.sbandIdx = (this.sbandIdx << 2) + 3;
    }

    public Subband(int w, int h, int ulcx, int ulcy, int lvls, WaveletFilter[] hfilters, WaveletFilter[] vfilters) {
        this.f43w = w;
        this.f42h = h;
        this.ulcx = ulcx;
        this.ulcy = ulcy;
        this.resLvl = lvls;
        Subband cur = this;
        for (int i = 0; i < lvls; i++) {
            cur = cur.split(hfilters[cur.resLvl <= hfilters.length ? cur.resLvl - 1 : hfilters.length - 1], vfilters[cur.resLvl <= vfilters.length ? cur.resLvl - 1 : vfilters.length - 1]);
        }
    }

    public Subband nextSubband() {
        if (this.isNode) {
            throw new IllegalArgumentException();
        }
        Subband sb;
        switch (this.orientation) {
            case 0:
                sb = getParent();
                if (sb == null || sb.resLvl != this.resLvl) {
                    return null;
                }
                return sb.getHL();
            case 1:
                return getParent().getLH();
            case 2:
                return getParent().getHH();
            case 3:
                sb = this;
                while (sb.orientation == 3) {
                    sb = sb.getParent();
                }
                switch (sb.orientation) {
                    case 0:
                        sb = sb.getParent();
                        if (sb != null && sb.resLvl == this.resLvl) {
                            sb = sb.getHL();
                            break;
                        }
                        return null;
                    case 1:
                        sb = sb.getParent().getLH();
                        break;
                    case 2:
                        sb = sb.getParent().getHH();
                        break;
                    default:
                        throw new Error("You have found a bug in JJ2000");
                }
                while (sb.isNode) {
                    sb = sb.getLL();
                }
                return sb;
            default:
                throw new Error("You have found a bug in JJ2000");
        }
    }

    public Subband getNextResLevel() {
        if (this.level == 0) {
            return null;
        }
        Subband sb = this;
        do {
            sb = sb.getParent();
            if (sb == null) {
                return null;
            }
        } while (sb.resLvl == this.resLvl);
        sb = sb.getHL();
        while (sb.isNode) {
            sb = sb.getLL();
        }
        return sb;
    }

    public Subband getSubbandByIdx(int rl, int sbi) {
        if (rl > this.resLvl || rl < 0) {
            throw new IllegalArgumentException("Resolution level index out of range");
        } else if (rl == sb.resLvl && sbi == sb.sbandIdx) {
            return sb;
        } else {
            if (sb.sbandIdx != 0) {
                sb = getParent();
            }
            while (sb.resLvl > rl) {
                sb = sb.getLL();
            }
            while (sb.resLvl < rl) {
                sb = sb.getParent();
            }
            switch (sbi) {
                case 1:
                    return sb.getHL();
                case 2:
                    return sb.getLH();
                case 3:
                    return sb.getHH();
                default:
                    return sb;
            }
        }
    }

    public Subband getSubband(int x, int y) {
        if (x < this.ulx || y < this.uly || x >= this.ulx + this.f43w || y >= this.uly + this.f42h) {
            throw new IllegalArgumentException();
        }
        Subband cur = this;
        while (cur.isNode) {
            Subband hhs = cur.getHH();
            if (x < hhs.ulx) {
                if (y < hhs.uly) {
                    cur = cur.getLL();
                } else {
                    cur = cur.getLH();
                }
            } else if (y < hhs.uly) {
                cur = cur.getHL();
            } else {
                cur = cur.getHH();
            }
        }
        return cur;
    }

    public String toString() {
        return "w=" + this.f43w + ",h=" + this.f42h + ",ulx=" + this.ulx + ",uly=" + this.uly + ",ulcx=" + this.ulcx + ",ulcy=" + this.ulcy + ",idx=" + this.sbandIdx + ",orient=" + this.orientation + ",node=" + this.isNode + ",level=" + this.level + ",resLvl=" + this.resLvl + ",nomCBlkW=" + this.nomCBlkW + ",nomCBlkH=" + this.nomCBlkH + ",numCb=" + this.numCb;
    }
}
