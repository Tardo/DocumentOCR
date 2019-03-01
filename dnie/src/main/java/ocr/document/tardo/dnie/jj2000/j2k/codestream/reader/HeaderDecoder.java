package jj2000.j2k.codestream.reader;

import colorspace.ChannelDefinitionMapper;
import colorspace.ColorSpace;
import colorspace.ColorSpaceException;
import colorspace.ColorSpaceMapper;
import colorspace.PalettizedColorSpaceMapper;
import colorspace.Resampler;
import custom.org.apache.harmony.security.fortress.PolicyUtils;
import icc.ICCProfileException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Hashtable;
import java.util.Vector;
import jj2000.j2k.NotImplementedError;
import jj2000.j2k.codestream.CorruptedCodestreamException;
import jj2000.j2k.codestream.HeaderInfo;
import jj2000.j2k.codestream.HeaderInfo.COC;
import jj2000.j2k.codestream.HeaderInfo.COD;
import jj2000.j2k.codestream.HeaderInfo.COM;
import jj2000.j2k.codestream.HeaderInfo.CRG;
import jj2000.j2k.codestream.HeaderInfo.POC;
import jj2000.j2k.codestream.HeaderInfo.QCC;
import jj2000.j2k.codestream.HeaderInfo.QCD;
import jj2000.j2k.codestream.HeaderInfo.RGN;
import jj2000.j2k.codestream.HeaderInfo.SIZ;
import jj2000.j2k.codestream.Markers;
import jj2000.j2k.codestream.ProgressionType;
import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.entropy.StdEntropyCoderOptions;
import jj2000.j2k.entropy.decoder.CodedCBlkDataSrcDec;
import jj2000.j2k.entropy.decoder.EntropyDecoder;
import jj2000.j2k.entropy.decoder.StdEntropyDecoder;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.Coord;
import jj2000.j2k.io.RandomAccessIO;
import jj2000.j2k.quantization.dequantizer.CBlkQuantDataSrcDec;
import jj2000.j2k.quantization.dequantizer.Dequantizer;
import jj2000.j2k.quantization.dequantizer.StdDequantizer;
import jj2000.j2k.quantization.dequantizer.StdDequantizerParams;
import jj2000.j2k.roi.MaxShiftSpec;
import jj2000.j2k.roi.ROIDeScaler;
import jj2000.j2k.util.FacilityManager;
import jj2000.j2k.util.ParameterList;
import jj2000.j2k.wavelet.synthesis.SynWTFilter;
import jj2000.j2k.wavelet.synthesis.SynWTFilterFloatLift9x7;
import jj2000.j2k.wavelet.synthesis.SynWTFilterIntLift5x3;

public class HeaderDecoder implements ProgressionType, Markers, StdEntropyCoderOptions {
    private static final int COC_FOUND = 4;
    private static final int COD_FOUND = 2;
    private static final int COM_FOUND = 2048;
    public static final int CRG_FOUND = 65536;
    public static final char OPT_PREFIX = 'H';
    private static final int PLM_FOUND = 32;
    private static final int PLT_FOUND = 128;
    private static final int POC_FOUND = 1024;
    public static final int PPM_FOUND = 16384;
    public static final int PPT_FOUND = 32768;
    private static final int QCC_FOUND = 256;
    private static final int QCD_FOUND = 8;
    private static final int RGN_FOUND = 512;
    private static final int SIZ_FOUND = 1;
    public static final int SOD_FOUND = 8192;
    private static final int SOT_FOUND = 64;
    private static final int TILE_RESET = -546;
    private static final int TLM_FOUND = 16;
    private static final String[][] pinfo = ((String[][]) null);
    private int cb0x = -1;
    private int cb0y = -1;
    private DecoderSpecs decSpec;
    private String hdStr = "";
    private HeaderInfo hi;
    private Hashtable ht = null;
    public int mainHeadOff;
    private int nCOCMarkSeg = 0;
    private int nCOMMarkSeg = 0;
    private int nComp;
    private int nPPMMarkSeg = 0;
    private int[][] nPPTMarkSeg = ((int[][]) null);
    private int nQCCMarkSeg = 0;
    private int nRGNMarkSeg = 0;
    public int[] nTileParts;
    private int nTiles;
    private int nfMarkSeg = 0;
    private byte[][] pPMMarkerData;
    private ByteArrayOutputStream[] pkdPktHeaders;
    boolean precinctPartitionIsUsed;
    public Vector tileOfTileParts;
    private byte[][][][] tilePartPkdPktHeaders;
    private boolean verbose;

    public int getMaxCompImgHeight() {
        return this.hi.siz.getMaxCompHeight();
    }

    public int getMaxCompImgWidth() {
        return this.hi.siz.getMaxCompWidth();
    }

    public final int getImgWidth() {
        return this.hi.siz.xsiz - this.hi.siz.x0siz;
    }

    public final int getImgHeight() {
        return this.hi.siz.ysiz - this.hi.siz.y0siz;
    }

    public final int getImgULX() {
        return this.hi.siz.x0siz;
    }

    public final int getImgULY() {
        return this.hi.siz.y0siz;
    }

    public final int getNomTileWidth() {
        return this.hi.siz.xtsiz;
    }

    public final int getNomTileHeight() {
        return this.hi.siz.ytsiz;
    }

    public final Coord getTilingOrigin(Coord co) {
        if (co == null) {
            return new Coord(this.hi.siz.xt0siz, this.hi.siz.yt0siz);
        }
        co.f36x = this.hi.siz.xt0siz;
        co.f37y = this.hi.siz.yt0siz;
        return co;
    }

    public final boolean isOriginalSigned(int c) {
        return this.hi.siz.isOrigSigned(c);
    }

    public final int getOriginalBitDepth(int c) {
        return this.hi.siz.getOrigBitDepth(c);
    }

    public final int getNumComps() {
        return this.nComp;
    }

    public final int getCompSubsX(int c) {
        return this.hi.siz.xrsiz[c];
    }

    public final int getCompSubsY(int c) {
        return this.hi.siz.yrsiz[c];
    }

    public final Dequantizer createDequantizer(CBlkQuantDataSrcDec src, int[] rb, DecoderSpecs decSpec2) {
        return new StdDequantizer(src, rb, decSpec2);
    }

    public final int getCbULX() {
        return this.cb0x;
    }

    public final int getCbULY() {
        return this.cb0y;
    }

    public final int getPPX(int t, int c, int rl) {
        return this.decSpec.pss.getPPX(t, c, rl);
    }

    public final int getPPY(int t, int c, int rl) {
        return this.decSpec.pss.getPPY(t, c, rl);
    }

    public final boolean precinctPartitionUsed() {
        return this.precinctPartitionIsUsed;
    }

    private SynWTFilter readFilter(DataInputStream ehs, int[] filtIdx) throws IOException {
        int kid = ehs.readUnsignedByte();
        filtIdx[0] = kid;
        if (kid >= 128) {
            throw new NotImplementedError("Custom filters not supported");
        }
        switch (kid) {
            case 0:
                return new SynWTFilterFloatLift9x7();
            case 1:
                return new SynWTFilterIntLift5x3();
            default:
                throw new CorruptedCodestreamException("Specified wavelet filter not JPEG 2000 part I compliant");
        }
    }

    public void checkMarkerLength(DataInputStream ehs, String str) throws IOException {
        if (ehs.available() != 0) {
            FacilityManager.getMsgLogger().printmsg(2, str + " length was short, attempting to resync.");
        }
    }

    private void readSIZ(DataInputStream ehs) throws IOException {
        SIZ ms = this.hi.getNewSIZ();
        this.hi.siz = ms;
        ms.lsiz = ehs.readUnsignedShort();
        ms.rsiz = ehs.readUnsignedShort();
        if (ms.rsiz > 2) {
            throw new Error("Codestream capabiities not JPEG 2000 - Part I compliant");
        }
        ms.xsiz = ehs.readInt();
        ms.ysiz = ehs.readInt();
        if (ms.xsiz <= 0 || ms.ysiz <= 0) {
            throw new IOException("JJ2000 does not support images whose width and/or height not in the range: 1 -- (2^31)-1");
        }
        ms.x0siz = ehs.readInt();
        ms.y0siz = ehs.readInt();
        if (ms.x0siz < 0 || ms.y0siz < 0) {
            throw new IOException("JJ2000 does not support images offset not in the range: 0 -- (2^31)-1");
        }
        ms.xtsiz = ehs.readInt();
        ms.ytsiz = ehs.readInt();
        if (ms.xtsiz <= 0 || ms.ytsiz <= 0) {
            throw new IOException("JJ2000 does not support tiles whose width and/or height are not in  the range: 1 -- (2^31)-1");
        }
        ms.xt0siz = ehs.readInt();
        ms.yt0siz = ehs.readInt();
        if (ms.xt0siz < 0 || ms.yt0siz < 0) {
            throw new IOException("JJ2000 does not support tiles whose offset is not in  the range: 0 -- (2^31)-1");
        }
        int readUnsignedShort = ehs.readUnsignedShort();
        ms.csiz = readUnsignedShort;
        this.nComp = readUnsignedShort;
        if (this.nComp < 1 || this.nComp > 16384) {
            throw new IllegalArgumentException("Number of component out of range 1--16384: " + this.nComp);
        }
        ms.ssiz = new int[this.nComp];
        ms.xrsiz = new int[this.nComp];
        ms.yrsiz = new int[this.nComp];
        for (int i = 0; i < this.nComp; i++) {
            ms.ssiz[i] = ehs.readUnsignedByte();
            ms.xrsiz[i] = ehs.readUnsignedByte();
            ms.yrsiz[i] = ehs.readUnsignedByte();
        }
        checkMarkerLength(ehs, "SIZ marker");
        this.nTiles = ms.getNumTiles();
        this.decSpec = new DecoderSpecs(this.nTiles, this.nComp);
    }

    private void readCRG(DataInputStream ehs) throws IOException {
        CRG ms = this.hi.getNewCRG();
        this.hi.crg = ms;
        ms.lcrg = ehs.readUnsignedShort();
        ms.xcrg = new int[this.nComp];
        ms.ycrg = new int[this.nComp];
        FacilityManager.getMsgLogger().printmsg(2, "Information in CRG marker segment not taken into account. This may affect the display of the decoded image.");
        for (int c = 0; c < this.nComp; c++) {
            ms.xcrg[c] = ehs.readUnsignedShort();
            ms.ycrg[c] = ehs.readUnsignedShort();
        }
        checkMarkerLength(ehs, "CRG marker");
    }

    private void readCOM(DataInputStream ehs, boolean mainh, int tileIdx, int comIdx) throws IOException {
        COM ms = this.hi.getNewCOM();
        ms.lcom = ehs.readUnsignedShort();
        ms.rcom = ehs.readUnsignedShort();
        switch (ms.rcom) {
            case 1:
                ms.ccom = new byte[(ms.lcom - 4)];
                for (int i = 0; i < ms.lcom - 4; i++) {
                    ms.ccom[i] = ehs.readByte();
                }
                break;
            default:
                FacilityManager.getMsgLogger().printmsg(2, "COM marker registered as 0x" + Integer.toHexString(ms.rcom) + " unknown, ignoring (this might crash the " + "decoder or decode a quality degraded or even " + "useless image)");
                ehs.skipBytes(ms.lcom - 4);
                break;
        }
        if (mainh) {
            this.hi.com.put("main_" + comIdx, ms);
        } else {
            this.hi.com.put("t" + tileIdx + "_" + comIdx, ms);
        }
        checkMarkerLength(ehs, "COM marker");
    }

    private void readQCD(DataInputStream ehs, boolean mainh, int tileIdx, int tpIdx) throws IOException {
        float[][] nStep = null;
        QCD ms = this.hi.getNewQCD();
        ms.lqcd = ehs.readUnsignedShort();
        ms.sqcd = ehs.readUnsignedByte();
        int guardBits = ms.getNumGuardBits();
        int qType = ms.getQuantType();
        if (mainh) {
            this.hi.qcd.put("main", ms);
            switch (qType) {
                case 0:
                    this.decSpec.qts.setDefault("reversible");
                    break;
                case 1:
                    this.decSpec.qts.setDefault("derived");
                    break;
                case 2:
                    this.decSpec.qts.setDefault("expounded");
                    break;
                default:
                    throw new CorruptedCodestreamException("Unknown or unsupported quantization style in Sqcd field, QCD marker main header");
            }
        }
        this.hi.qcd.put("t" + tileIdx, ms);
        switch (qType) {
            case 0:
                this.decSpec.qts.setTileDef(tileIdx, "reversible");
                break;
            case 1:
                this.decSpec.qts.setTileDef(tileIdx, "derived");
                break;
            case 2:
                this.decSpec.qts.setTileDef(tileIdx, "expounded");
                break;
            default:
                throw new CorruptedCodestreamException("Unknown or unsupported quantization style in Sqcd field, QCD marker, tile header");
        }
        StdDequantizerParams qParms = new StdDequantizerParams();
        int maxrl;
        int[][] exp;
        int rl;
        int minb;
        int maxb;
        int hpd;
        int j;
        int[] iArr;
        int tmp;
        if (qType == 0) {
            if (mainh) {
                maxrl = ((Integer) this.decSpec.dls.getDefault()).intValue();
            } else {
                maxrl = ((Integer) this.decSpec.dls.getTileDef(tileIdx)).intValue();
            }
            exp = new int[(maxrl + 1)][];
            qParms.exp = exp;
            ms.spqcd = (int[][]) Array.newInstance(Integer.TYPE, new int[]{maxrl + 1, 4});
            for (rl = 0; rl <= maxrl; rl++) {
                if (rl == 0) {
                    minb = 0;
                    maxb = 1;
                } else {
                    if (1 > maxrl - rl) {
                        hpd = 1 - (maxrl - rl);
                    } else {
                        hpd = 1;
                    }
                    minb = 1 << ((hpd - 1) << 1);
                    maxb = 1 << (hpd << 1);
                }
                exp[rl] = new int[maxb];
                for (j = minb; j < maxb; j++) {
                    iArr = ms.spqcd[rl];
                    tmp = ehs.readUnsignedByte();
                    iArr[j] = tmp;
                    exp[rl][j] = (tmp >> 3) & 31;
                }
            }
        } else {
            maxrl = qType == 1 ? 0 : mainh ? ((Integer) this.decSpec.dls.getDefault()).intValue() : ((Integer) this.decSpec.dls.getTileDef(tileIdx)).intValue();
            exp = new int[(maxrl + 1)][];
            qParms.exp = exp;
            nStep = new float[(maxrl + 1)][];
            qParms.nStep = nStep;
            ms.spqcd = (int[][]) Array.newInstance(Integer.TYPE, new int[]{maxrl + 1, 4});
            for (rl = 0; rl <= maxrl; rl++) {
                if (rl == 0) {
                    minb = 0;
                    maxb = 1;
                } else {
                    if (1 > maxrl - rl) {
                        hpd = 1 - (maxrl - rl);
                    } else {
                        hpd = 1;
                    }
                    minb = 1 << ((hpd - 1) << 1);
                    maxb = 1 << (hpd << 1);
                }
                exp[rl] = new int[maxb];
                nStep[rl] = new float[maxb];
                for (j = minb; j < maxb; j++) {
                    iArr = ms.spqcd[rl];
                    tmp = ehs.readUnsignedShort();
                    iArr[j] = tmp;
                    exp[rl][j] = (tmp >> 11) & 31;
                    nStep[rl][j] = (-1.0f - (((float) (tmp & 2047)) / 2048.0f)) / ((float) (-1 << exp[rl][j]));
                }
            }
        }
        if (mainh) {
            this.decSpec.qsss.setDefault(qParms);
            this.decSpec.gbs.setDefault(new Integer(guardBits));
        } else {
            this.decSpec.qsss.setTileDef(tileIdx, qParms);
            this.decSpec.gbs.setTileDef(tileIdx, new Integer(guardBits));
        }
        checkMarkerLength(ehs, "QCD marker");
    }

    private void readQCC(DataInputStream ehs, boolean mainh, int tileIdx, int tpIdx) throws IOException {
        int cComp;
        float[][] nStepC = null;
        QCC ms = this.hi.getNewQCC();
        ms.lqcc = ehs.readUnsignedShort();
        if (this.nComp < 257) {
            cComp = ehs.readUnsignedByte();
            ms.cqcc = cComp;
        } else {
            cComp = ehs.readUnsignedShort();
            ms.cqcc = cComp;
        }
        if (cComp >= this.nComp) {
            throw new CorruptedCodestreamException("Invalid component index in QCC marker");
        }
        ms.sqcc = ehs.readUnsignedByte();
        int guardBits = ms.getNumGuardBits();
        int qType = ms.getQuantType();
        if (mainh) {
            this.hi.qcc.put("main_c" + cComp, ms);
            switch (qType) {
                case 0:
                    this.decSpec.qts.setCompDef(cComp, "reversible");
                    break;
                case 1:
                    this.decSpec.qts.setCompDef(cComp, "derived");
                    break;
                case 2:
                    this.decSpec.qts.setCompDef(cComp, "expounded");
                    break;
                default:
                    throw new CorruptedCodestreamException("Unknown or unsupported quantization style in Sqcd field, QCD marker, main header");
            }
        }
        this.hi.qcc.put("t" + tileIdx + "_c" + cComp, ms);
        switch (qType) {
            case 0:
                this.decSpec.qts.setTileCompVal(tileIdx, cComp, "reversible");
                break;
            case 1:
                this.decSpec.qts.setTileCompVal(tileIdx, cComp, "derived");
                break;
            case 2:
                this.decSpec.qts.setTileCompVal(tileIdx, cComp, "expounded");
                break;
            default:
                throw new CorruptedCodestreamException("Unknown or unsupported quantization style in Sqcd field, QCD marker, main header");
        }
        StdDequantizerParams qParms = new StdDequantizerParams();
        int maxrl;
        int[][] expC;
        int rl;
        int minb;
        int maxb;
        int hpd;
        int j;
        int[] iArr;
        int tmp;
        if (qType == 0) {
            if (mainh) {
                maxrl = ((Integer) this.decSpec.dls.getCompDef(cComp)).intValue();
            } else {
                maxrl = ((Integer) this.decSpec.dls.getTileCompVal(tileIdx, cComp)).intValue();
            }
            expC = new int[(maxrl + 1)][];
            qParms.exp = expC;
            ms.spqcc = (int[][]) Array.newInstance(Integer.TYPE, new int[]{maxrl + 1, 4});
            for (rl = 0; rl <= maxrl; rl++) {
                if (rl == 0) {
                    minb = 0;
                    maxb = 1;
                } else {
                    if (1 > maxrl - rl) {
                        hpd = 1 - (maxrl - rl);
                    } else {
                        hpd = 1;
                    }
                    minb = 1 << ((hpd - 1) << 1);
                    maxb = 1 << (hpd << 1);
                }
                expC[rl] = new int[maxb];
                for (j = minb; j < maxb; j++) {
                    iArr = ms.spqcc[rl];
                    tmp = ehs.readUnsignedByte();
                    iArr[j] = tmp;
                    expC[rl][j] = (tmp >> 3) & 31;
                }
            }
        } else {
            maxrl = qType == 1 ? 0 : mainh ? ((Integer) this.decSpec.dls.getCompDef(cComp)).intValue() : ((Integer) this.decSpec.dls.getTileCompVal(tileIdx, cComp)).intValue();
            nStepC = new float[(maxrl + 1)][];
            qParms.nStep = nStepC;
            expC = new int[(maxrl + 1)][];
            qParms.exp = expC;
            ms.spqcc = (int[][]) Array.newInstance(Integer.TYPE, new int[]{maxrl + 1, 4});
            for (rl = 0; rl <= maxrl; rl++) {
                if (rl == 0) {
                    minb = 0;
                    maxb = 1;
                } else {
                    if (1 > maxrl - rl) {
                        hpd = 1 - (maxrl - rl);
                    } else {
                        hpd = 1;
                    }
                    minb = 1 << ((hpd - 1) << 1);
                    maxb = 1 << (hpd << 1);
                }
                expC[rl] = new int[maxb];
                nStepC[rl] = new float[maxb];
                for (j = minb; j < maxb; j++) {
                    iArr = ms.spqcc[rl];
                    tmp = ehs.readUnsignedShort();
                    iArr[j] = tmp;
                    expC[rl][j] = (tmp >> 11) & 31;
                    nStepC[rl][j] = (-1.0f - (((float) (tmp & 2047)) / 2048.0f)) / ((float) (-1 << expC[rl][j]));
                }
            }
        }
        if (mainh) {
            this.decSpec.qsss.setCompDef(cComp, qParms);
            this.decSpec.gbs.setCompDef(cComp, new Integer(guardBits));
        } else {
            this.decSpec.qsss.setTileCompVal(tileIdx, cComp, qParms);
            this.decSpec.gbs.setTileCompVal(tileIdx, cComp, new Integer(guardBits));
        }
        checkMarkerLength(ehs, "QCC marker");
    }

    private void readCOD(DataInputStream ehs, boolean mainh, int tileIdx, int tpIdx) throws IOException {
        COD ms = this.hi.getNewCOD();
        ms.lcod = ehs.readUnsignedShort();
        int cstyle = ehs.readUnsignedByte();
        ms.scod = cstyle;
        if ((cstyle & 1) != 0) {
            this.precinctPartitionIsUsed = true;
            cstyle &= -2;
        } else {
            this.precinctPartitionIsUsed = false;
        }
        if (mainh) {
            this.hi.cod.put("main", ms);
            if ((cstyle & 2) != 0) {
                this.decSpec.sops.setDefault(new Boolean(PolicyUtils.TRUE));
                cstyle &= -3;
            } else {
                this.decSpec.sops.setDefault(new Boolean(PolicyUtils.FALSE));
            }
        } else {
            this.hi.cod.put("t" + tileIdx, ms);
            if ((cstyle & 2) != 0) {
                this.decSpec.sops.setTileDef(tileIdx, new Boolean(PolicyUtils.TRUE));
                cstyle &= -3;
            } else {
                this.decSpec.sops.setTileDef(tileIdx, new Boolean(PolicyUtils.FALSE));
            }
        }
        if (mainh) {
            if ((cstyle & 4) != 0) {
                this.decSpec.ephs.setDefault(new Boolean(PolicyUtils.TRUE));
                cstyle &= -5;
            } else {
                this.decSpec.ephs.setDefault(new Boolean(PolicyUtils.FALSE));
            }
        } else if ((cstyle & 4) != 0) {
            this.decSpec.ephs.setTileDef(tileIdx, new Boolean(PolicyUtils.TRUE));
            cstyle &= -5;
        } else {
            this.decSpec.ephs.setTileDef(tileIdx, new Boolean(PolicyUtils.FALSE));
        }
        if ((cstyle & 24) != 0) {
            FacilityManager.getMsgLogger().printmsg(2, "Code-block partition origin different from (0,0). This is defined in JPEG 2000 part 2 and may not be supported by all JPEG 2000 decoders.");
        }
        if ((cstyle & 8) != 0) {
            if (this.cb0x == -1 || this.cb0x != 0) {
                this.cb0x = 1;
                cstyle &= -9;
            } else {
                throw new IllegalArgumentException("Code-block partition origin redefined in new COD marker segment. Not supported by JJ2000");
            }
        } else if (this.cb0x == -1 || this.cb0x != 1) {
            this.cb0x = 0;
        } else {
            throw new IllegalArgumentException("Code-block partition origin redefined in new COD marker segment. Not supported by JJ2000");
        }
        if ((cstyle & 16) != 0) {
            if (this.cb0y == -1 || this.cb0y != 0) {
                this.cb0y = 1;
                cstyle &= -17;
            } else {
                throw new IllegalArgumentException("Code-block partition origin redefined in new COD marker segment. Not supported by JJ2000");
            }
        } else if (this.cb0y == -1 || this.cb0y != 1) {
            this.cb0y = 0;
        } else {
            throw new IllegalArgumentException("Code-block partition origin redefined in new COD marker segment. Not supported by JJ2000");
        }
        ms.sgcod_po = ehs.readUnsignedByte();
        ms.sgcod_nl = ehs.readUnsignedShort();
        if (ms.sgcod_nl <= 0 || ms.sgcod_nl > 65535) {
            throw new CorruptedCodestreamException("Number of layers out of range: 1--65535");
        }
        ms.sgcod_mct = ehs.readUnsignedByte();
        int mrl = ehs.readUnsignedByte();
        ms.spcod_ndl = mrl;
        if (mrl > 32) {
            throw new CorruptedCodestreamException("Number of decomposition levels out of range: 0--32");
        }
        cblk = new Integer[2];
        ms.spcod_cw = ehs.readUnsignedByte();
        cblk[0] = new Integer(1 << (ms.spcod_cw + 2));
        if (cblk[0].intValue() < 4 || cblk[0].intValue() > 1024) {
            throw new CorruptedCodestreamException("Non-valid code-block width in SPcod field, COD marker");
        }
        ms.spcod_ch = ehs.readUnsignedByte();
        cblk[1] = new Integer(1 << (ms.spcod_ch + 2));
        if (cblk[1].intValue() < 4 || cblk[1].intValue() > 1024) {
            throw new CorruptedCodestreamException("Non-valid code-block height in SPcod field, COD marker");
        } else if (cblk[0].intValue() * cblk[1].intValue() > 4096) {
            throw new CorruptedCodestreamException("Non-valid code-block area in SPcod field, COD marker");
        } else {
            if (mainh) {
                this.decSpec.cblks.setDefault(cblk);
            } else {
                this.decSpec.cblks.setTileDef(tileIdx, cblk);
            }
            int ecOptions = ehs.readUnsignedByte();
            ms.spcod_cs = ecOptions;
            if ((ecOptions & -64) != 0) {
                throw new CorruptedCodestreamException("Unknown \"code-block style\" in SPcod field, COD marker: 0x" + Integer.toHexString(ecOptions));
            }
            SynWTFilter[] hfilters = new SynWTFilter[1];
            SynWTFilter[] vfilters = new SynWTFilter[1];
            hfilters[0] = readFilter(ehs, ms.spcod_t);
            vfilters[0] = hfilters[0];
            SynWTFilter[][] hvfilters = new SynWTFilter[][]{hfilters, vfilters};
            Vector[] v = new Vector[]{new Vector(), new Vector()};
            if (this.precinctPartitionIsUsed) {
                ms.spcod_ps = new int[(mrl + 1)];
                for (int rl = mrl; rl >= 0; rl--) {
                    int[] iArr = ms.spcod_ps;
                    int i = mrl - rl;
                    int val = ehs.readUnsignedByte();
                    iArr[i] = val;
                    v[0].insertElementAt(new Integer(1 << (val & 15)), 0);
                    v[1].insertElementAt(new Integer(1 << ((val & 240) >> 4)), 0);
                }
            } else {
                v[0].addElement(new Integer(32768));
                v[1].addElement(new Integer(32768));
            }
            if (mainh) {
                this.decSpec.pss.setDefault(v);
            } else {
                this.decSpec.pss.setTileDef(tileIdx, v);
            }
            this.precinctPartitionIsUsed = true;
            checkMarkerLength(ehs, "COD marker");
            if (mainh) {
                this.decSpec.wfs.setDefault(hvfilters);
                this.decSpec.dls.setDefault(new Integer(mrl));
                this.decSpec.ecopts.setDefault(new Integer(ecOptions));
                this.decSpec.cts.setDefault(new Integer(ms.sgcod_mct));
                this.decSpec.nls.setDefault(new Integer(ms.sgcod_nl));
                this.decSpec.pos.setDefault(new Integer(ms.sgcod_po));
                return;
            }
            this.decSpec.wfs.setTileDef(tileIdx, hvfilters);
            this.decSpec.dls.setTileDef(tileIdx, new Integer(mrl));
            this.decSpec.ecopts.setTileDef(tileIdx, new Integer(ecOptions));
            this.decSpec.cts.setTileDef(tileIdx, new Integer(ms.sgcod_mct));
            this.decSpec.nls.setTileDef(tileIdx, new Integer(ms.sgcod_nl));
            this.decSpec.pos.setTileDef(tileIdx, new Integer(ms.sgcod_po));
        }
    }

    private void readCOC(DataInputStream ehs, boolean mainh, int tileIdx, int tpIdx) throws IOException {
        int cComp;
        COC ms = this.hi.getNewCOC();
        ms.lcoc = ehs.readUnsignedShort();
        if (this.nComp < 257) {
            cComp = ehs.readUnsignedByte();
            ms.ccoc = cComp;
        } else {
            cComp = ehs.readUnsignedShort();
            ms.ccoc = cComp;
        }
        if (cComp >= this.nComp) {
            throw new CorruptedCodestreamException("Invalid component index in QCC marker");
        }
        int cstyle = ehs.readUnsignedByte();
        ms.scoc = cstyle;
        if ((cstyle & 1) != 0) {
            this.precinctPartitionIsUsed = true;
            cstyle &= -2;
        } else {
            this.precinctPartitionIsUsed = false;
        }
        int mrl = ehs.readUnsignedByte();
        ms.spcoc_ndl = mrl;
        cblk = new Integer[2];
        ms.spcoc_cw = ehs.readUnsignedByte();
        cblk[0] = new Integer(1 << (ms.spcoc_cw + 2));
        if (cblk[0].intValue() < 4 || cblk[0].intValue() > 1024) {
            throw new CorruptedCodestreamException("Non-valid code-block width in SPcod field, COC marker");
        }
        ms.spcoc_ch = ehs.readUnsignedByte();
        cblk[1] = new Integer(1 << (ms.spcoc_ch + 2));
        if (cblk[1].intValue() < 4 || cblk[1].intValue() > 1024) {
            throw new CorruptedCodestreamException("Non-valid code-block height in SPcod field, COC marker");
        } else if (cblk[0].intValue() * cblk[1].intValue() > 4096) {
            throw new CorruptedCodestreamException("Non-valid code-block area in SPcod field, COC marker");
        } else {
            if (mainh) {
                this.decSpec.cblks.setCompDef(cComp, cblk);
            } else {
                this.decSpec.cblks.setTileCompVal(tileIdx, cComp, cblk);
            }
            int ecOptions = ehs.readUnsignedByte();
            ms.spcoc_cs = ecOptions;
            if ((ecOptions & -64) != 0) {
                throw new CorruptedCodestreamException("Unknown \"code-block context\" in SPcoc field, COC marker: 0x" + Integer.toHexString(ecOptions));
            }
            SynWTFilter[] hfilters = new SynWTFilter[1];
            SynWTFilter[] vfilters = new SynWTFilter[1];
            hfilters[0] = readFilter(ehs, ms.spcoc_t);
            vfilters[0] = hfilters[0];
            SynWTFilter[][] hvfilters = new SynWTFilter[][]{hfilters, vfilters};
            Vector[] v = new Vector[]{new Vector(), new Vector()};
            if (this.precinctPartitionIsUsed) {
                ms.spcoc_ps = new int[(mrl + 1)];
                for (int rl = mrl; rl >= 0; rl--) {
                    int[] iArr = ms.spcoc_ps;
                    int val = ehs.readUnsignedByte();
                    iArr[rl] = val;
                    v[0].insertElementAt(new Integer(1 << (val & 15)), 0);
                    v[1].insertElementAt(new Integer(1 << ((val & 240) >> 4)), 0);
                }
            } else {
                v[0].addElement(new Integer(32768));
                v[1].addElement(new Integer(32768));
            }
            if (mainh) {
                this.decSpec.pss.setCompDef(cComp, v);
            } else {
                this.decSpec.pss.setTileCompVal(tileIdx, cComp, v);
            }
            this.precinctPartitionIsUsed = true;
            checkMarkerLength(ehs, "COD marker");
            if (mainh) {
                this.hi.coc.put("main_c" + cComp, ms);
                this.decSpec.wfs.setCompDef(cComp, hvfilters);
                this.decSpec.dls.setCompDef(cComp, new Integer(mrl));
                this.decSpec.ecopts.setCompDef(cComp, new Integer(ecOptions));
                return;
            }
            this.hi.coc.put("t" + tileIdx + "_c" + cComp, ms);
            this.decSpec.wfs.setTileCompVal(tileIdx, cComp, hvfilters);
            this.decSpec.dls.setTileCompVal(tileIdx, cComp, new Integer(mrl));
            this.decSpec.ecopts.setTileCompVal(tileIdx, cComp, new Integer(ecOptions));
        }
    }

    private void readPOC(DataInputStream ehs, boolean mainh, int t, int tpIdx) throws IOException {
        POC ms;
        int[][] change;
        int chg;
        boolean useShort = this.nComp >= 256;
        int nOldChg = 0;
        if (mainh || this.hi.poc.get("t" + t) == null) {
            ms = this.hi.getNewPOC();
        } else {
            ms = (POC) this.hi.poc.get("t" + t);
            nOldChg = ms.rspoc.length;
        }
        ms.lpoc = ehs.readUnsignedShort();
        int newChg = (ms.lpoc - 2) / ((useShort ? 4 : 2) + 5);
        int ntotChg = nOldChg + newChg;
        if (nOldChg != 0) {
            change = (int[][]) Array.newInstance(Integer.TYPE, new int[]{ntotChg, 6});
            int[] tmprspoc = new int[ntotChg];
            int[] tmpcspoc = new int[ntotChg];
            int[] tmplyepoc = new int[ntotChg];
            int[] tmprepoc = new int[ntotChg];
            int[] tmpcepoc = new int[ntotChg];
            int[] tmpppoc = new int[ntotChg];
            int[][] prevChg = (int[][]) this.decSpec.pcs.getTileDef(t);
            for (chg = 0; chg < nOldChg; chg++) {
                change[chg] = prevChg[chg];
                tmprspoc[chg] = ms.rspoc[chg];
                tmpcspoc[chg] = ms.cspoc[chg];
                tmplyepoc[chg] = ms.lyepoc[chg];
                tmprepoc[chg] = ms.repoc[chg];
                tmpcepoc[chg] = ms.cepoc[chg];
                tmpppoc[chg] = ms.ppoc[chg];
            }
            ms.rspoc = tmprspoc;
            ms.cspoc = tmpcspoc;
            ms.lyepoc = tmplyepoc;
            ms.repoc = tmprepoc;
            ms.cepoc = tmpcepoc;
            ms.ppoc = tmpppoc;
        } else {
            change = (int[][]) Array.newInstance(Integer.TYPE, new int[]{newChg, 6});
            ms.rspoc = new int[newChg];
            ms.cspoc = new int[newChg];
            ms.lyepoc = new int[newChg];
            ms.repoc = new int[newChg];
            ms.cepoc = new int[newChg];
            ms.ppoc = new int[newChg];
        }
        for (chg = nOldChg; chg < ntotChg; chg++) {
            int[] iArr = change[chg];
            int[] iArr2 = ms.rspoc;
            int readUnsignedByte = ehs.readUnsignedByte();
            iArr2[chg] = readUnsignedByte;
            iArr[0] = readUnsignedByte;
            if (useShort) {
                iArr = change[chg];
                iArr2 = ms.cspoc;
                readUnsignedByte = ehs.readUnsignedShort();
                iArr2[chg] = readUnsignedByte;
                iArr[1] = readUnsignedByte;
            } else {
                iArr = change[chg];
                iArr2 = ms.cspoc;
                readUnsignedByte = ehs.readUnsignedByte();
                iArr2[chg] = readUnsignedByte;
                iArr[1] = readUnsignedByte;
            }
            iArr = change[chg];
            iArr2 = ms.lyepoc;
            readUnsignedByte = ehs.readUnsignedShort();
            iArr2[chg] = readUnsignedByte;
            iArr[2] = readUnsignedByte;
            if (change[chg][2] < 1) {
                throw new CorruptedCodestreamException("LYEpoc value must be greater than 1 in POC marker segment of tile " + t + ", tile-part " + tpIdx);
            }
            iArr = change[chg];
            iArr2 = ms.repoc;
            readUnsignedByte = ehs.readUnsignedByte();
            iArr2[chg] = readUnsignedByte;
            iArr[3] = readUnsignedByte;
            if (change[chg][3] <= change[chg][0]) {
                throw new CorruptedCodestreamException("REpoc value must be greater than RSpoc in POC marker segment of tile " + t + ", tile-part " + tpIdx);
            }
            if (useShort) {
                iArr = change[chg];
                iArr2 = ms.cepoc;
                readUnsignedByte = ehs.readUnsignedShort();
                iArr2[chg] = readUnsignedByte;
                iArr[4] = readUnsignedByte;
            } else {
                iArr = ms.cepoc;
                int tmp = ehs.readUnsignedByte();
                iArr[chg] = tmp;
                if (tmp == 0) {
                    change[chg][4] = 0;
                } else {
                    change[chg][4] = tmp;
                }
            }
            if (change[chg][4] <= change[chg][1]) {
                throw new CorruptedCodestreamException("CEpoc value must be greater than CSpoc in POC marker segment of tile " + t + ", tile-part " + tpIdx);
            }
            iArr = change[chg];
            iArr2 = ms.ppoc;
            readUnsignedByte = ehs.readUnsignedByte();
            iArr2[chg] = readUnsignedByte;
            iArr[5] = readUnsignedByte;
        }
        checkMarkerLength(ehs, "POC marker");
        if (mainh) {
            this.hi.poc.put("main", ms);
            this.decSpec.pcs.setDefault(change);
            return;
        }
        this.hi.poc.put("t" + t, ms);
        this.decSpec.pcs.setTileDef(t, change);
    }

    private void readTLM(DataInputStream ehs) throws IOException {
        ehs.skipBytes(ehs.readUnsignedShort() - 2);
        FacilityManager.getMsgLogger().printmsg(1, "Skipping unsupported TLM marker");
    }

    private void readPLM(DataInputStream ehs) throws IOException {
        ehs.skipBytes(ehs.readUnsignedShort() - 2);
        FacilityManager.getMsgLogger().printmsg(1, "Skipping unsupported PLM marker");
    }

    private void readPLTFields(DataInputStream ehs) throws IOException {
        ehs.skipBytes(ehs.readUnsignedShort() - 2);
        FacilityManager.getMsgLogger().printmsg(1, "Skipping unsupported PLT marker");
    }

    private void readRGN(DataInputStream ehs, boolean mainh, int tileIdx, int tpIdx) throws IOException {
        RGN ms = this.hi.getNewRGN();
        ms.lrgn = ehs.readUnsignedShort();
        int comp = this.nComp < 257 ? ehs.readUnsignedByte() : ehs.readUnsignedShort();
        ms.crgn = comp;
        if (comp >= this.nComp) {
            throw new CorruptedCodestreamException("Invalid component index in RGN marker" + comp);
        }
        ms.srgn = ehs.readUnsignedByte();
        if (ms.srgn != 0) {
            throw new CorruptedCodestreamException("Unknown or unsupported Srgn parameter in ROI marker");
        }
        if (this.decSpec.rois == null) {
            this.decSpec.rois = new MaxShiftSpec(this.nTiles, this.nComp, (byte) 2);
        }
        ms.sprgn = ehs.readUnsignedByte();
        if (mainh) {
            this.hi.rgn.put("main_c" + comp, ms);
            this.decSpec.rois.setCompDef(comp, new Integer(ms.sprgn));
        } else {
            this.hi.rgn.put("t" + tileIdx + "_c" + comp, ms);
            this.decSpec.rois.setTileCompVal(tileIdx, comp, new Integer(ms.sprgn));
        }
        checkMarkerLength(ehs, "RGN marker");
    }

    private void readPPM(DataInputStream ehs) throws IOException {
        if (this.pPMMarkerData == null) {
            this.pPMMarkerData = new byte[this.nPPMMarkSeg][];
            this.tileOfTileParts = new Vector();
            this.decSpec.pphs.setDefault(new Boolean(true));
        }
        int remSegLen = ehs.readUnsignedShort() - 3;
        int indx = ehs.readUnsignedByte();
        this.pPMMarkerData[indx] = new byte[remSegLen];
        ehs.read(this.pPMMarkerData[indx], 0, remSegLen);
        checkMarkerLength(ehs, "PPM marker");
    }

    private void readPPT(DataInputStream ehs, int tile, int tpIdx) throws IOException {
        if (this.tilePartPkdPktHeaders == null) {
            this.tilePartPkdPktHeaders = new byte[this.nTiles][][][];
        }
        if (this.tilePartPkdPktHeaders[tile] == null) {
            this.tilePartPkdPktHeaders[tile] = new byte[this.nTileParts[tile]][][];
        }
        if (this.tilePartPkdPktHeaders[tile][tpIdx] == null) {
            this.tilePartPkdPktHeaders[tile][tpIdx] = new byte[this.nPPTMarkSeg[tile][tpIdx]][];
        }
        int curMarkSegLen = ehs.readUnsignedShort();
        int indx = ehs.readUnsignedByte();
        byte[] temp = new byte[(curMarkSegLen - 3)];
        ehs.read(temp);
        this.tilePartPkdPktHeaders[tile][tpIdx][indx] = temp;
        checkMarkerLength(ehs, "PPT marker");
        this.decSpec.pphs.setTileDef(tile, new Boolean(true));
    }

    private void extractMainMarkSeg(short marker, RandomAccessIO ehs) throws IOException {
        if (this.nfMarkSeg != 0 || marker == Markers.SIZ) {
            String htKey = "";
            if (this.ht == null) {
                this.ht = new Hashtable();
            }
            StringBuilder append;
            int i;
            switch (marker) {
                case (short) -175:
                    if ((this.nfMarkSeg & 1) == 0) {
                        this.nfMarkSeg |= 1;
                        htKey = "SIZ";
                        break;
                    }
                    throw new CorruptedCodestreamException("More than one SIZ marker segment found in main header");
                case (short) -174:
                    if ((this.nfMarkSeg & 2) == 0) {
                        this.nfMarkSeg |= 2;
                        htKey = "COD";
                        break;
                    }
                    throw new CorruptedCodestreamException("More than one COD marker found in main header");
                case (short) -173:
                    this.nfMarkSeg |= 4;
                    append = new StringBuilder().append("COC");
                    i = this.nCOCMarkSeg;
                    this.nCOCMarkSeg = i + 1;
                    htKey = append.append(i).toString();
                    break;
                case (short) -171:
                    if ((this.nfMarkSeg & 16) == 0) {
                        this.nfMarkSeg |= 16;
                        break;
                    }
                    throw new CorruptedCodestreamException("More than one TLM marker found in main header");
                case (short) -169:
                    if ((this.nfMarkSeg & 32) == 0) {
                        FacilityManager.getMsgLogger().printmsg(2, "PLM marker segment found but not used by by JJ2000 decoder.");
                        this.nfMarkSeg |= 32;
                        htKey = "PLM";
                        break;
                    }
                    throw new CorruptedCodestreamException("More than one PLM marker found in main header");
                case (short) -168:
                    throw new CorruptedCodestreamException("PLT found in main header");
                case (short) -164:
                    if ((this.nfMarkSeg & 8) == 0) {
                        this.nfMarkSeg |= 8;
                        htKey = "QCD";
                        break;
                    }
                    throw new CorruptedCodestreamException("More than one QCD marker found in main header");
                case (short) -163:
                    this.nfMarkSeg |= 256;
                    append = new StringBuilder().append("QCC");
                    i = this.nQCCMarkSeg;
                    this.nQCCMarkSeg = i + 1;
                    htKey = append.append(i).toString();
                    break;
                case (short) -162:
                    this.nfMarkSeg |= 512;
                    append = new StringBuilder().append("RGN");
                    i = this.nRGNMarkSeg;
                    this.nRGNMarkSeg = i + 1;
                    htKey = append.append(i).toString();
                    break;
                case (short) -161:
                    if ((this.nfMarkSeg & 1024) == 0) {
                        this.nfMarkSeg |= 1024;
                        htKey = "POC";
                        break;
                    }
                    throw new CorruptedCodestreamException("More than one POC marker segment found in main header");
                case (short) -160:
                    this.nfMarkSeg |= 16384;
                    append = new StringBuilder().append("PPM");
                    i = this.nPPMMarkSeg;
                    this.nPPMMarkSeg = i + 1;
                    htKey = append.append(i).toString();
                    break;
                case (short) -159:
                    throw new CorruptedCodestreamException("PPT found in main header");
                case (short) -157:
                    if ((this.nfMarkSeg & 65536) == 0) {
                        this.nfMarkSeg |= 65536;
                        htKey = "CRG";
                        break;
                    }
                    throw new CorruptedCodestreamException("More than one CRG marker found in main header");
                case (short) -156:
                    this.nfMarkSeg |= 2048;
                    append = new StringBuilder().append("COM");
                    i = this.nCOMMarkSeg;
                    this.nCOMMarkSeg = i + 1;
                    htKey = append.append(i).toString();
                    break;
                case (short) -112:
                    if ((this.nfMarkSeg & 64) != 0) {
                        throw new CorruptedCodestreamException("More than one SOT marker found right after main or tile header");
                    }
                    this.nfMarkSeg |= 64;
                    return;
                case (short) -109:
                    throw new CorruptedCodestreamException("SOD found in main header");
                case (short) -39:
                    throw new CorruptedCodestreamException("EOC found in main header");
                default:
                    htKey = "UNKNOWN";
                    FacilityManager.getMsgLogger().printmsg(2, "Non recognized marker segment (0x" + Integer.toHexString(marker) + ") in main header!");
                    break;
            }
            if (marker < (short) -208 || marker > (short) -193) {
                int markSegLen = ehs.readUnsignedShort();
                byte[] buf = new byte[markSegLen];
                buf[0] = (byte) ((markSegLen >> 8) & 255);
                buf[1] = (byte) (markSegLen & 255);
                ehs.readFully(buf, 2, markSegLen - 2);
                if (!htKey.equals("UNKNOWN")) {
                    this.ht.put(htKey, buf);
                    return;
                }
                return;
            }
            return;
        }
        throw new CorruptedCodestreamException("First marker after SOC must be SIZ " + Integer.toHexString(marker));
    }

    public void extractTilePartMarkSeg(short marker, RandomAccessIO ehs, int tileIdx, int tilePartIdx) throws IOException {
        String htKey = "";
        if (this.ht == null) {
            this.ht = new Hashtable();
        }
        StringBuilder append;
        int i;
        switch (marker) {
            case (short) -175:
                throw new CorruptedCodestreamException("SIZ found in tile-part header");
            case (short) -174:
                if ((this.nfMarkSeg & 2) == 0) {
                    this.nfMarkSeg |= 2;
                    htKey = "COD";
                    break;
                }
                throw new CorruptedCodestreamException("More than one COD marker found in tile-part header");
            case (short) -173:
                this.nfMarkSeg |= 4;
                append = new StringBuilder().append("COC");
                i = this.nCOCMarkSeg;
                this.nCOCMarkSeg = i + 1;
                htKey = append.append(i).toString();
                break;
            case (short) -171:
                throw new CorruptedCodestreamException("TLM found in tile-part header");
            case (short) -169:
                throw new CorruptedCodestreamException("PLM found in tile-part header");
            case (short) -168:
                if ((this.nfMarkSeg & 32) == 0) {
                    FacilityManager.getMsgLogger().printmsg(2, "PLT marker segment found but not used by JJ2000 decoder.");
                    htKey = "UNKNOWN";
                    break;
                }
                throw new CorruptedCodestreamException("PLT marker found eventhough PLM marker found in main header");
            case (short) -164:
                if ((this.nfMarkSeg & 8) == 0) {
                    this.nfMarkSeg |= 8;
                    htKey = "QCD";
                    break;
                }
                throw new CorruptedCodestreamException("More than one QCD marker found in tile-part header");
            case (short) -163:
                this.nfMarkSeg |= 256;
                append = new StringBuilder().append("QCC");
                i = this.nQCCMarkSeg;
                this.nQCCMarkSeg = i + 1;
                htKey = append.append(i).toString();
                break;
            case (short) -162:
                this.nfMarkSeg |= 512;
                append = new StringBuilder().append("RGN");
                i = this.nRGNMarkSeg;
                this.nRGNMarkSeg = i + 1;
                htKey = append.append(i).toString();
                break;
            case (short) -161:
                if ((this.nfMarkSeg & 1024) == 0) {
                    this.nfMarkSeg |= 1024;
                    htKey = "POC";
                    break;
                }
                throw new CorruptedCodestreamException("More than one POC marker segment found in tile-part header");
            case (short) -160:
                throw new CorruptedCodestreamException("PPM found in tile-part header");
            case (short) -159:
                this.nfMarkSeg |= 32768;
                if (this.nPPTMarkSeg == null) {
                    this.nPPTMarkSeg = new int[this.nTiles][];
                }
                if (this.nPPTMarkSeg[tileIdx] == null) {
                    this.nPPTMarkSeg[tileIdx] = new int[this.nTileParts[tileIdx]];
                }
                append = new StringBuilder().append("PPT");
                int[] iArr = this.nPPTMarkSeg[tileIdx];
                int i2 = iArr[tilePartIdx];
                iArr[tilePartIdx] = i2 + 1;
                htKey = append.append(i2).toString();
                break;
            case (short) -157:
                throw new CorruptedCodestreamException("CRG marker found in tile-part header");
            case (short) -156:
                this.nfMarkSeg |= 2048;
                append = new StringBuilder().append("COM");
                i = this.nCOMMarkSeg;
                this.nCOMMarkSeg = i + 1;
                htKey = append.append(i).toString();
                break;
            case (short) -112:
                throw new CorruptedCodestreamException("Second SOT marker segment found in tile-part header");
            case (short) -109:
                this.nfMarkSeg |= 8192;
                return;
            case (short) -39:
                throw new CorruptedCodestreamException("EOC found in tile-part header");
            default:
                htKey = "UNKNOWN";
                FacilityManager.getMsgLogger().printmsg(2, "Non recognized marker segment (0x" + Integer.toHexString(marker) + ") in tile-part header" + " of tile " + tileIdx + " !");
                break;
        }
        int markSegLen = ehs.readUnsignedShort();
        byte[] buf = new byte[markSegLen];
        buf[0] = (byte) ((markSegLen >> 8) & 255);
        buf[1] = (byte) (markSegLen & 255);
        ehs.readFully(buf, 2, markSegLen - 2);
        if (!htKey.equals("UNKNOWN")) {
            this.ht.put(htKey, buf);
        }
    }

    private void readFoundMainMarkSeg() throws IOException {
        int i;
        if ((this.nfMarkSeg & 1) != 0) {
            readSIZ(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("SIZ"))));
        }
        if ((this.nfMarkSeg & 2048) != 0) {
            for (i = 0; i < this.nCOMMarkSeg; i++) {
                readCOM(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("COM" + i))), true, 0, i);
            }
        }
        if ((this.nfMarkSeg & 65536) != 0) {
            readCRG(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("CRG"))));
        }
        if ((this.nfMarkSeg & 2) != 0) {
            readCOD(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("COD"))), true, 0, 0);
        }
        if ((this.nfMarkSeg & 4) != 0) {
            for (i = 0; i < this.nCOCMarkSeg; i++) {
                readCOC(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("COC" + i))), true, 0, 0);
            }
        }
        if ((this.nfMarkSeg & 512) != 0) {
            for (i = 0; i < this.nRGNMarkSeg; i++) {
                readRGN(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("RGN" + i))), true, 0, 0);
            }
        }
        if ((this.nfMarkSeg & 8) != 0) {
            readQCD(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("QCD"))), true, 0, 0);
        }
        if ((this.nfMarkSeg & 256) != 0) {
            for (i = 0; i < this.nQCCMarkSeg; i++) {
                readQCC(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("QCC" + i))), true, 0, 0);
            }
        }
        if ((this.nfMarkSeg & 1024) != 0) {
            readPOC(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("POC"))), true, 0, 0);
        }
        if ((this.nfMarkSeg & 16384) != 0) {
            for (i = 0; i < this.nPPMMarkSeg; i++) {
                readPPM(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("PPM" + i))));
            }
        }
        this.ht = null;
    }

    public void readFoundTilePartMarkSeg(int tileIdx, int tpIdx) throws IOException {
        int i;
        if ((this.nfMarkSeg & 2) != 0) {
            readCOD(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("COD"))), false, tileIdx, tpIdx);
        }
        if ((this.nfMarkSeg & 4) != 0) {
            for (i = 0; i < this.nCOCMarkSeg; i++) {
                readCOC(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("COC" + i))), false, tileIdx, tpIdx);
            }
        }
        if ((this.nfMarkSeg & 512) != 0) {
            for (i = 0; i < this.nRGNMarkSeg; i++) {
                readRGN(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("RGN" + i))), false, tileIdx, tpIdx);
            }
        }
        if ((this.nfMarkSeg & 8) != 0) {
            readQCD(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("QCD"))), false, tileIdx, tpIdx);
        }
        if ((this.nfMarkSeg & 256) != 0) {
            for (i = 0; i < this.nQCCMarkSeg; i++) {
                readQCC(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("QCC" + i))), false, tileIdx, tpIdx);
            }
        }
        if ((this.nfMarkSeg & 1024) != 0) {
            readPOC(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("POC"))), false, tileIdx, tpIdx);
        }
        if ((this.nfMarkSeg & 2048) != 0) {
            for (i = 0; i < this.nCOMMarkSeg; i++) {
                readCOM(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("COM" + i))), false, tileIdx, i);
            }
        }
        if ((this.nfMarkSeg & 32768) != 0) {
            for (i = 0; i < this.nPPTMarkSeg[tileIdx][tpIdx]; i++) {
                readPPT(new DataInputStream(new ByteArrayInputStream((byte[]) this.ht.get("PPT" + i))), tileIdx, tpIdx);
            }
        }
        this.ht = null;
    }

    public DecoderSpecs getDecoderSpecs() {
        return this.decSpec;
    }

    public HeaderDecoder(RandomAccessIO ehs, ParameterList pl, HeaderInfo hi) throws IOException {
        this.hi = hi;
        this.verbose = this.verbose;
        pl.checkList((char) OPT_PREFIX, ParameterList.toNameArray(pinfo));
        this.mainHeadOff = ehs.getPos();
        if (ehs.readShort() != Markers.SOC) {
            throw new CorruptedCodestreamException("SOC marker segment not  found at the beginning of the codestream.");
        }
        this.nfMarkSeg = 0;
        do {
            extractMainMarkSeg(ehs.readShort(), ehs);
        } while ((this.nfMarkSeg & 64) == 0);
        ehs.seek(ehs.getPos() - 2);
        readFoundMainMarkSeg();
    }

    public EntropyDecoder createEntropyDecoder(CodedCBlkDataSrcDec src, ParameterList pl) {
        pl.checkList((char) EntropyDecoder.OPT_PREFIX, ParameterList.toNameArray(EntropyDecoder.getParameterInfo()));
        return new StdEntropyDecoder(src, this.decSpec, pl.getBooleanParameter("Cer"), pl.getBooleanParameter("Cverber"), pl.getIntParameter("m_quit"));
    }

    public BlkImgDataSrc createColorSpaceMapper(BlkImgDataSrc src, ColorSpace csMap) throws IOException, ICCProfileException, ColorSpaceException {
        return ColorSpaceMapper.createInstance(src, csMap);
    }

    public BlkImgDataSrc createChannelDefinitionMapper(BlkImgDataSrc src, ColorSpace csMap) throws IOException, ColorSpaceException {
        return ChannelDefinitionMapper.createInstance(src, csMap);
    }

    public BlkImgDataSrc createPalettizedColorSpaceMapper(BlkImgDataSrc src, ColorSpace csMap) throws IOException, ColorSpaceException {
        return PalettizedColorSpaceMapper.createInstance(src, csMap);
    }

    public BlkImgDataSrc createResampler(BlkImgDataSrc src, ColorSpace csMap) throws IOException, ColorSpaceException {
        return Resampler.createInstance(src, csMap);
    }

    public ROIDeScaler createROIDeScaler(CBlkQuantDataSrcDec src, ParameterList pl, DecoderSpecs decSpec2) {
        return ROIDeScaler.createInstance(src, pl, decSpec2);
    }

    public void resetHeaderMarkers() {
        this.nfMarkSeg &= 16416;
        this.nCOCMarkSeg = 0;
        this.nQCCMarkSeg = 0;
        this.nCOMMarkSeg = 0;
        this.nRGNMarkSeg = 0;
    }

    public String toString() {
        return this.hdStr;
    }

    public static String[][] getParameterInfo() {
        return pinfo;
    }

    public int getNumTiles() {
        return this.nTiles;
    }

    public ByteArrayInputStream getPackedPktHead(int tile) throws IOException {
        if (this.pkdPktHeaders == null) {
            int i;
            this.pkdPktHeaders = new ByteArrayOutputStream[this.nTiles];
            for (i = this.nTiles - 1; i >= 0; i--) {
                this.pkdPktHeaders[i] = new ByteArrayOutputStream();
            }
            int t;
            if (this.nPPMMarkSeg != 0) {
                int nTileParts = this.tileOfTileParts.size();
                ByteArrayOutputStream allNppmIppm = new ByteArrayOutputStream();
                for (i = 0; i < this.nPPMMarkSeg; i++) {
                    allNppmIppm.write(this.pPMMarkerData[i]);
                }
                ByteArrayInputStream pph = new ByteArrayInputStream(allNppmIppm.toByteArray());
                for (i = 0; i < nTileParts; i++) {
                    t = ((Integer) this.tileOfTileParts.elementAt(i)).intValue();
                    byte[] temp = new byte[((((pph.read() << 24) | (pph.read() << 16)) | (pph.read() << 8)) | pph.read())];
                    pph.read(temp);
                    this.pkdPktHeaders[t].write(temp);
                }
            } else {
                for (t = this.nTiles - 1; t >= 0; t--) {
                    for (int tp = 0; tp < this.nTileParts[t]; tp++) {
                        for (i = 0; i < this.nPPTMarkSeg[t][tp]; i++) {
                            this.pkdPktHeaders[t].write(this.tilePartPkdPktHeaders[t][tp][i]);
                        }
                    }
                }
            }
        }
        return new ByteArrayInputStream(this.pkdPktHeaders[tile].toByteArray());
    }

    public void setTileOfTileParts(int tile) {
        if (this.nPPMMarkSeg != 0) {
            this.tileOfTileParts.addElement(new Integer(tile));
        }
    }

    public int getNumFoundMarkSeg() {
        return this.nfMarkSeg;
    }
}
