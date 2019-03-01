package jj2000.j2k.wavelet.synthesis;

import jj2000.j2k.wavelet.Subband;
import jj2000.j2k.wavelet.WaveletFilter;

public class SubbandSyn extends Subband {
    public SynWTFilter hFilter;
    public int magbits = 0;
    private SubbandSyn parent;
    private SubbandSyn subb_HH;
    private SubbandSyn subb_HL;
    private SubbandSyn subb_LH;
    private SubbandSyn subb_LL;
    public SynWTFilter vFilter;

    public SubbandSyn(int w, int h, int ulcx, int ulcy, int lvls, WaveletFilter[] hfilters, WaveletFilter[] vfilters) {
        super(w, h, ulcx, ulcy, lvls, hfilters, vfilters);
    }

    public Subband getParent() {
        return this.parent;
    }

    public Subband getLL() {
        return this.subb_LL;
    }

    public Subband getHL() {
        return this.subb_HL;
    }

    public Subband getLH() {
        return this.subb_LH;
    }

    public Subband getHH() {
        return this.subb_HH;
    }

    protected Subband split(WaveletFilter hfilter, WaveletFilter vfilter) {
        if (this.isNode) {
            throw new IllegalArgumentException();
        }
        this.isNode = true;
        this.hFilter = (SynWTFilter) hfilter;
        this.vFilter = (SynWTFilter) vfilter;
        this.subb_LL = new SubbandSyn();
        this.subb_LH = new SubbandSyn();
        this.subb_HL = new SubbandSyn();
        this.subb_HH = new SubbandSyn();
        this.subb_LL.parent = this;
        this.subb_HL.parent = this;
        this.subb_LH.parent = this;
        this.subb_HH.parent = this;
        initChilds();
        return this.subb_LL;
    }

    public WaveletFilter getHorWFilter() {
        return this.hFilter;
    }

    public WaveletFilter getVerWFilter() {
        return this.hFilter;
    }
}
