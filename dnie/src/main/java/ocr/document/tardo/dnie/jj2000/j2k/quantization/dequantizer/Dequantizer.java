package jj2000.j2k.quantization.dequantizer;

import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.image.CompTransfSpec;
import jj2000.j2k.image.invcomptransf.InvCompTransf;
import jj2000.j2k.wavelet.synthesis.CBlkWTDataSrcDec;
import jj2000.j2k.wavelet.synthesis.MultiResImgDataAdapter;
import jj2000.j2k.wavelet.synthesis.SubbandSyn;
import jj2000.j2k.wavelet.synthesis.SynWTFilterSpec;

public abstract class Dequantizer extends MultiResImgDataAdapter implements CBlkWTDataSrcDec {
    public static final char OPT_PREFIX = 'Q';
    private static final String[][] pinfo = ((String[][]) null);
    private CompTransfSpec cts;
    protected int[] rb = null;
    protected CBlkQuantDataSrcDec src;
    protected int[] utrb = null;
    private SynWTFilterSpec wfs;

    public Dequantizer(CBlkQuantDataSrcDec src, int[] utrb, DecoderSpecs decSpec) {
        super(src);
        if (utrb.length != src.getNumComps()) {
            throw new IllegalArgumentException();
        }
        this.src = src;
        this.utrb = utrb;
        this.cts = decSpec.cts;
        this.wfs = decSpec.wfs;
    }

    public int getNomRangeBits(int c) {
        return this.rb[c];
    }

    public SubbandSyn getSynSubbandTree(int t, int c) {
        return this.src.getSynSubbandTree(t, c);
    }

    public int getCbULX() {
        return this.src.getCbULX();
    }

    public int getCbULY() {
        return this.src.getCbULY();
    }

    public static String[][] getParameterInfo() {
        return pinfo;
    }

    public void setTile(int x, int y) {
        int cttype;
        this.src.setTile(x, y);
        this.tIdx = getTileIdx();
        if (((Integer) this.cts.getTileDef(this.tIdx)).intValue() == 0) {
            cttype = 0;
        } else {
            int rev = 0;
            for (int c = 0; c < (this.src.getNumComps() > 3 ? 3 : this.src.getNumComps()); c++) {
                rev += this.wfs.isReversible(this.tIdx, c) ? 1 : 0;
            }
            if (rev == 3) {
                cttype = 1;
            } else if (rev == 0) {
                cttype = 2;
            } else {
                throw new IllegalArgumentException("Wavelet transformation and component transformation not coherent in tile" + this.tIdx);
            }
        }
        switch (cttype) {
            case 0:
                this.rb = this.utrb;
                return;
            case 1:
                this.rb = InvCompTransf.calcMixedBitDepths(this.utrb, 1, null);
                return;
            case 2:
                this.rb = InvCompTransf.calcMixedBitDepths(this.utrb, 2, null);
                return;
            default:
                throw new IllegalArgumentException("Non JPEG 2000 part I component transformation for tile: " + this.tIdx);
        }
    }

    public void nextTile() {
        this.src.nextTile();
        this.tIdx = getTileIdx();
        switch (((Integer) this.cts.getTileDef(this.tIdx)).intValue()) {
            case 0:
                this.rb = this.utrb;
                return;
            case 1:
                this.rb = InvCompTransf.calcMixedBitDepths(this.utrb, 1, null);
                return;
            case 2:
                this.rb = InvCompTransf.calcMixedBitDepths(this.utrb, 2, null);
                return;
            default:
                throw new IllegalArgumentException("Non JPEG 2000 part I component transformation for tile: " + this.tIdx);
        }
    }
}
