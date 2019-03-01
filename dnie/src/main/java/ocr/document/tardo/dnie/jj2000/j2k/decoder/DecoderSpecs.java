package jj2000.j2k.decoder;

import jj2000.j2k.IntegerSpec;
import jj2000.j2k.ModuleSpec;
import jj2000.j2k.entropy.CBlkSizeSpec;
import jj2000.j2k.entropy.PrecinctSizeSpec;
import jj2000.j2k.image.CompTransfSpec;
import jj2000.j2k.quantization.GuardBitsSpec;
import jj2000.j2k.quantization.QuantStepSizeSpec;
import jj2000.j2k.quantization.QuantTypeSpec;
import jj2000.j2k.roi.MaxShiftSpec;
import jj2000.j2k.wavelet.synthesis.SynWTFilterSpec;

public class DecoderSpecs implements Cloneable {
    public CBlkSizeSpec cblks;
    public CompTransfSpec cts;
    public IntegerSpec dls;
    public ModuleSpec ecopts;
    public ModuleSpec ephs;
    public ModuleSpec ers;
    public GuardBitsSpec gbs;
    public ModuleSpec iccs;
    public IntegerSpec nls;
    public ModuleSpec pcs;
    public IntegerSpec pos;
    public ModuleSpec pphs;
    public PrecinctSizeSpec pss;
    public QuantStepSizeSpec qsss;
    public QuantTypeSpec qts;
    public MaxShiftSpec rois;
    public ModuleSpec sops;
    public SynWTFilterSpec wfs;

    public DecoderSpecs getCopy() {
        try {
            DecoderSpecs decSpec2 = (DecoderSpecs) clone();
            decSpec2.qts = (QuantTypeSpec) this.qts.getCopy();
            decSpec2.qsss = (QuantStepSizeSpec) this.qsss.getCopy();
            decSpec2.gbs = (GuardBitsSpec) this.gbs.getCopy();
            decSpec2.wfs = (SynWTFilterSpec) this.wfs.getCopy();
            decSpec2.dls = (IntegerSpec) this.dls.getCopy();
            decSpec2.cts = (CompTransfSpec) this.cts.getCopy();
            if (this.rois != null) {
                decSpec2.rois = (MaxShiftSpec) this.rois.getCopy();
            }
            return decSpec2;
        } catch (CloneNotSupportedException e) {
            throw new Error("Cannot clone the DecoderSpecs instance");
        }
    }

    public DecoderSpecs(int nt, int nc) {
        this.qts = new QuantTypeSpec(nt, nc, (byte) 2);
        this.qsss = new QuantStepSizeSpec(nt, nc, (byte) 2);
        this.gbs = new GuardBitsSpec(nt, nc, (byte) 2);
        this.wfs = new SynWTFilterSpec(nt, nc, (byte) 2);
        this.dls = new IntegerSpec(nt, nc, (byte) 2);
        this.cts = new CompTransfSpec(nt, nc, (byte) 2);
        this.ecopts = new ModuleSpec(nt, nc, (byte) 2);
        this.ers = new ModuleSpec(nt, nc, (byte) 2);
        this.cblks = new CBlkSizeSpec(nt, nc, (byte) 2);
        this.pss = new PrecinctSizeSpec(nt, nc, (byte) 2, this.dls);
        this.nls = new IntegerSpec(nt, nc, (byte) 1);
        this.pos = new IntegerSpec(nt, nc, (byte) 1);
        this.pcs = new ModuleSpec(nt, nc, (byte) 1);
        this.sops = new ModuleSpec(nt, nc, (byte) 1);
        this.ephs = new ModuleSpec(nt, nc, (byte) 1);
        this.pphs = new ModuleSpec(nt, nc, (byte) 1);
        this.iccs = new ModuleSpec(nt, nc, (byte) 1);
        this.pphs.setDefault(new Boolean(false));
    }
}
