package jj2000.j2k.codestream.reader;

import java.io.IOException;
import jj2000.j2k.codestream.HeaderInfo;
import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.entropy.decoder.CodedCBlkDataSrcDec;
import jj2000.j2k.image.Coord;
import jj2000.j2k.io.RandomAccessIO;
import jj2000.j2k.quantization.dequantizer.StdDequantizerParams;
import jj2000.j2k.util.MathUtil;
import jj2000.j2k.util.ParameterList;
import jj2000.j2k.wavelet.synthesis.SubbandSyn;

public abstract class BitstreamReaderAgent implements CodedCBlkDataSrcDec {
    public static final char OPT_PREFIX = 'B';
    private static final String[][] pinfo = ((String[][]) null);
    protected int anbytes;
    protected float arate;
    protected final int ax;
    protected final int ay;
    protected int ctX;
    protected int ctY;
    protected final int[] culx;
    protected final int[] culy;
    protected DecoderSpecs decSpec;
    protected boolean[] derived = null;
    protected int[] gb = null;
    protected final HeaderDecoder hd;
    protected final int imgH;
    protected final int imgW;
    protected int[] mdl;
    protected final int nc;
    protected final int nt;
    protected final int ntH;
    protected final int ntW;
    protected final int ntX;
    protected final int ntY;
    protected final int[] offX;
    protected final int[] offY;
    protected StdDequantizerParams[] params = null;
    protected final int px;
    protected final int py;
    protected SubbandSyn[] subbTrees;
    protected int targetRes;
    protected int tnbytes;
    protected float trate;

    public abstract void nextTile();

    public abstract void setTile(int i, int i2);

    protected BitstreamReaderAgent(HeaderDecoder hd, DecoderSpecs decSpec) {
        this.decSpec = decSpec;
        this.hd = hd;
        this.nc = hd.getNumComps();
        this.offX = new int[this.nc];
        this.offY = new int[this.nc];
        this.culx = new int[this.nc];
        this.culy = new int[this.nc];
        this.imgW = hd.getImgWidth();
        this.imgH = hd.getImgHeight();
        this.ax = hd.getImgULX();
        this.ay = hd.getImgULY();
        Coord co = hd.getTilingOrigin(null);
        this.px = co.f36x;
        this.py = co.f37y;
        this.ntW = hd.getNomTileWidth();
        this.ntH = hd.getNomTileHeight();
        this.ntX = ((((this.ax + this.imgW) - this.px) + this.ntW) - 1) / this.ntW;
        this.ntY = ((((this.ay + this.imgH) - this.py) + this.ntH) - 1) / this.ntH;
        this.nt = this.ntX * this.ntY;
    }

    public final int getCbULX() {
        return this.hd.getCbULX();
    }

    public int getCbULY() {
        return this.hd.getCbULY();
    }

    public final int getNumComps() {
        return this.nc;
    }

    public final int getCompSubsX(int c) {
        return this.hd.getCompSubsX(c);
    }

    public int getCompSubsY(int c) {
        return this.hd.getCompSubsY(c);
    }

    public int getTileWidth(int rl) {
        int mindl = this.decSpec.dls.getMinInTile(getTileIdx());
        if (rl > mindl) {
            throw new IllegalArgumentException("Requested resolution level is not available for, at least, one component in tile: " + this.ctX + "x" + this.ctY);
        }
        int dl = mindl - rl;
        return ((((1 << dl) + (this.ctX < this.ntX + -1 ? this.px + ((this.ctX + 1) * this.ntW) : this.ax + this.imgW)) - 1) / (1 << dl)) - ((((1 << dl) + (this.ctX == 0 ? this.ax : this.px + (this.ctX * this.ntW))) - 1) / (1 << dl));
    }

    public int getTileHeight(int rl) {
        int mindl = this.decSpec.dls.getMinInTile(getTileIdx());
        if (rl > mindl) {
            throw new IllegalArgumentException("Requested resolution level is not available for, at least, one component in tile: " + this.ctX + "x" + this.ctY);
        }
        int dl = mindl - rl;
        return ((((1 << dl) + (this.ctY < this.ntY + -1 ? this.py + ((this.ctY + 1) * this.ntH) : this.ay + this.imgH)) - 1) / (1 << dl)) - ((((1 << dl) + (this.ctY == 0 ? this.ay : this.py + (this.ctY * this.ntH))) - 1) / (1 << dl));
    }

    public int getImgWidth(int rl) {
        int mindl = this.decSpec.dls.getMin();
        if (rl > mindl) {
            throw new IllegalArgumentException("Requested resolution level is not available for, at least, one tile-component");
        }
        int dl = mindl - rl;
        return ((((this.ax + this.imgW) + (1 << dl)) - 1) / (1 << dl)) - (((this.ax + (1 << dl)) - 1) / (1 << dl));
    }

    public int getImgHeight(int rl) {
        int mindl = this.decSpec.dls.getMin();
        if (rl > mindl) {
            throw new IllegalArgumentException("Requested resolution level is not available for, at least, one tile-component");
        }
        int dl = mindl - rl;
        return ((((this.ay + this.imgH) + (1 << dl)) - 1) / (1 << dl)) - (((this.ay + (1 << dl)) - 1) / (1 << dl));
    }

    public int getImgULX(int rl) {
        int mindl = this.decSpec.dls.getMin();
        if (rl > mindl) {
            throw new IllegalArgumentException("Requested resolution level is not available for, at least, one tile-component");
        }
        int dl = mindl - rl;
        return ((this.ax + (1 << dl)) - 1) / (1 << dl);
    }

    public int getImgULY(int rl) {
        int mindl = this.decSpec.dls.getMin();
        if (rl > mindl) {
            throw new IllegalArgumentException("Requested resolution level is not available for, at least, one tile-component");
        }
        int dl = mindl - rl;
        return ((this.ay + (1 << dl)) - 1) / (1 << dl);
    }

    public final int getTileCompWidth(int t, int c, int rl) {
        if (t != getTileIdx()) {
            throw new Error("Asking the tile-component width of a tile different  from the current one.");
        }
        int dl = this.mdl[c] - rl;
        return ((((1 << dl) + (((this.hd.getCompSubsX(c) + (this.ctX < this.ntX + -1 ? this.px + ((this.ctX + 1) * this.ntW) : this.ax + this.imgW)) - 1) / this.hd.getCompSubsX(c))) - 1) / (1 << dl)) - (((this.culx[c] + (1 << dl)) - 1) / (1 << dl));
    }

    public final int getTileCompHeight(int t, int c, int rl) {
        if (t != getTileIdx()) {
            throw new Error("Asking the tile-component width of a tile different  from the current one.");
        }
        int dl = this.mdl[c] - rl;
        return ((((1 << dl) + (((this.hd.getCompSubsY(c) + (this.ctY < this.ntY + -1 ? this.py + ((this.ctY + 1) * this.ntH) : this.ay + this.imgH)) - 1) / this.hd.getCompSubsY(c))) - 1) / (1 << dl)) - (((this.culy[c] + (1 << dl)) - 1) / (1 << dl));
    }

    public final int getCompImgWidth(int c, int rl) {
        int dl = this.decSpec.dls.getMinInComp(c) - rl;
        return ((((1 << dl) + ((((this.ax + this.imgW) + this.hd.getCompSubsX(c)) - 1) / this.hd.getCompSubsX(c))) - 1) / (1 << dl)) - ((((1 << dl) + (((this.ax + this.hd.getCompSubsX(c)) - 1) / this.hd.getCompSubsX(c))) - 1) / (1 << dl));
    }

    public final int getCompImgHeight(int c, int rl) {
        int dl = this.decSpec.dls.getMinInComp(c) - rl;
        return ((((1 << dl) + ((((this.ay + this.imgH) + this.hd.getCompSubsY(c)) - 1) / this.hd.getCompSubsY(c))) - 1) / (1 << dl)) - ((((1 << dl) + (((this.ay + this.hd.getCompSubsY(c)) - 1) / this.hd.getCompSubsY(c))) - 1) / (1 << dl));
    }

    public final Coord getTile(Coord co) {
        if (co == null) {
            return new Coord(this.ctX, this.ctY);
        }
        co.f36x = this.ctX;
        co.f37y = this.ctY;
        return co;
    }

    public final int getTileIdx() {
        return (this.ctY * this.ntX) + this.ctX;
    }

    public final int getResULX(int c, int rl) {
        int dl = this.mdl[c] - rl;
        if (dl >= 0) {
            return (int) Math.ceil(((double) ((int) Math.ceil(((double) Math.max(this.px + (this.ctX * this.ntW), this.ax)) / ((double) getCompSubsX(c))))) / ((double) (1 << dl)));
        }
        throw new IllegalArgumentException("Requested resolution level is not available for, at least, one component in tile: " + this.ctX + "x" + this.ctY);
    }

    public final int getResULY(int c, int rl) {
        int dl = this.mdl[c] - rl;
        if (dl >= 0) {
            return (int) Math.ceil(((double) ((int) Math.ceil(((double) Math.max(this.py + (this.ctY * this.ntH), this.ay)) / ((double) getCompSubsY(c))))) / ((double) (1 << dl)));
        }
        throw new IllegalArgumentException("Requested resolution level is not available for, at least, one component in tile: " + this.ctX + "x" + this.ctY);
    }

    public final Coord getNumTiles(Coord co) {
        if (co == null) {
            return new Coord(this.ntX, this.ntY);
        }
        co.f36x = this.ntX;
        co.f37y = this.ntY;
        return co;
    }

    public final int getNumTiles() {
        return this.ntX * this.ntY;
    }

    public final SubbandSyn getSynSubbandTree(int t, int c) {
        if (t != getTileIdx()) {
            throw new IllegalArgumentException("Can not request subband tree of a different tile than the current one");
        } else if (c >= 0 && c < this.nc) {
            return this.subbTrees[c];
        } else {
            throw new IllegalArgumentException("Component index out of range");
        }
    }

    public static BitstreamReaderAgent createInstance(RandomAccessIO in, HeaderDecoder hd, ParameterList pl, DecoderSpecs decSpec, boolean cdstrInfo, HeaderInfo hi) throws IOException {
        pl.checkList((char) OPT_PREFIX, ParameterList.toNameArray(getParameterInfo()));
        return new FileBitstreamReaderAgent(hd, in, decSpec, pl, cdstrInfo, hi);
    }

    public static String[][] getParameterInfo() {
        return pinfo;
    }

    public final int getPPX(int t, int c, int rl) {
        return this.decSpec.pss.getPPX(t, c, rl);
    }

    public final int getPPY(int t, int c, int rl) {
        return this.decSpec.pss.getPPY(t, c, rl);
    }

    protected void initSubbandsFields(int c, SubbandSyn sb) {
        int t = getTileIdx();
        int rl = sb.resLvl;
        int cbw = this.decSpec.cblks.getCBlkWidth((byte) 3, t, c);
        int cbh = this.decSpec.cblks.getCBlkHeight((byte) 3, t, c);
        if (sb.isNode) {
            initSubbandsFields(c, (SubbandSyn) sb.getLL());
            initSubbandsFields(c, (SubbandSyn) sb.getHL());
            initSubbandsFields(c, (SubbandSyn) sb.getLH());
            initSubbandsFields(c, (SubbandSyn) sb.getHH());
            return;
        }
        if (this.hd.precinctPartitionUsed()) {
            int ppxExp = MathUtil.log2(getPPX(t, c, rl));
            int ppyExp = MathUtil.log2(getPPY(t, c, rl));
            int cbwExp = MathUtil.log2(cbw);
            int cbhExp = MathUtil.log2(cbh);
            switch (sb.resLvl) {
                case 0:
                    sb.nomCBlkW = cbwExp < ppxExp ? 1 << cbwExp : 1 << ppxExp;
                    sb.nomCBlkH = cbhExp < ppyExp ? 1 << cbhExp : 1 << ppyExp;
                    break;
                default:
                    sb.nomCBlkW = cbwExp < ppxExp + -1 ? 1 << cbwExp : 1 << (ppxExp - 1);
                    sb.nomCBlkH = cbhExp < ppyExp + -1 ? 1 << cbhExp : 1 << (ppyExp - 1);
                    break;
            }
        }
        sb.nomCBlkW = cbw;
        sb.nomCBlkH = cbh;
        if (sb.numCb == null) {
            sb.numCb = new Coord();
        }
        if (sb.w == 0 || sb.h == 0) {
            sb.numCb.f36x = 0;
            sb.numCb.f37y = 0;
        } else {
            int acb0x = getCbULX();
            int acb0y = getCbULY();
            switch (sb.sbandIdx) {
                case 0:
                    break;
                case 1:
                    acb0x = 0;
                    break;
                case 2:
                    acb0y = 0;
                    break;
                case 3:
                    acb0x = 0;
                    acb0y = 0;
                    break;
                default:
                    throw new Error("Internal JJ2000 error");
            }
            if (sb.ulcx - acb0x < 0 || sb.ulcy - acb0y < 0) {
                throw new IllegalArgumentException("Invalid code-blocks partition origin or image offset in the reference grid.");
            }
            int tmp = (sb.ulcx - acb0x) + sb.nomCBlkW;
            sb.numCb.f36x = (((sb.w + tmp) - 1) / sb.nomCBlkW) - ((tmp / sb.nomCBlkW) - 1);
            tmp = (sb.ulcy - acb0y) + sb.nomCBlkH;
            sb.numCb.f37y = (((sb.h + tmp) - 1) / sb.nomCBlkH) - ((tmp / sb.nomCBlkH) - 1);
        }
        if (this.derived[c]) {
            sb.magbits = (this.gb[c] + (this.params[c].exp[0][0] - (this.mdl[c] - sb.level))) - 1;
        } else {
            sb.magbits = (this.gb[c] + this.params[c].exp[sb.resLvl][sb.sbandIdx]) - 1;
        }
    }

    public int getImgRes() {
        return this.targetRes;
    }

    public float getTargetRate() {
        return this.trate;
    }

    public float getActualRate() {
        this.arate = ((((float) this.anbytes) * 8.0f) / ((float) this.hd.getMaxCompImgWidth())) / ((float) this.hd.getMaxCompImgHeight());
        return this.arate;
    }

    public int getTargetNbytes() {
        return this.tnbytes;
    }

    public int getActualNbytes() {
        return this.anbytes;
    }

    public int getTilePartULX() {
        return this.hd.getTilingOrigin(null).f36x;
    }

    public int getTilePartULY() {
        return this.hd.getTilingOrigin(null).f37y;
    }

    public int getNomTileWidth() {
        return this.hd.getNomTileWidth();
    }

    public int getNomTileHeight() {
        return this.hd.getNomTileHeight();
    }
}
