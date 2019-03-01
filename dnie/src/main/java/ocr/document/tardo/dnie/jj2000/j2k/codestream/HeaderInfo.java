package jj2000.j2k.codestream;

import java.util.Hashtable;
import jj2000.j2k.wavelet.FilterTypes;
import org.bouncycastle.asn1.eac.CertificateBody;

public class HeaderInfo implements Markers, ProgressionType, FilterTypes, Cloneable {
    public Hashtable coc = new Hashtable();
    public Hashtable cod = new Hashtable();
    public Hashtable com = new Hashtable();
    public CRG crg;
    private int ncom = 0;
    public Hashtable poc = new Hashtable();
    public Hashtable qcc = new Hashtable();
    public Hashtable qcd = new Hashtable();
    public Hashtable rgn = new Hashtable();
    public SIZ siz;
    public Hashtable sot = new Hashtable();

    public class COC {
        public int ccoc;
        public int lcoc;
        public int scoc;
        public int spcoc_ch;
        public int spcoc_cs;
        public int spcoc_cw;
        public int spcoc_ndl;
        public int[] spcoc_ps;
        public int[] spcoc_t = new int[1];

        public String toString() {
            String str = (("\n --- COC (" + this.lcoc + " bytes) ---\n") + " Component      : " + this.ccoc + "\n") + " Coding style   : ";
            if (this.scoc == 0) {
                str = str + "Default";
            } else {
                if ((this.scoc & 1) != 0) {
                    str = str + "Precints ";
                }
                if ((this.scoc & 2) != 0) {
                    str = str + "SOP ";
                }
                if ((this.scoc & 4) != 0) {
                    str = str + "EPH ";
                }
            }
            str = (str + "\n") + " Cblk style     : ";
            if (this.spcoc_cs == 0) {
                str = str + "Default";
            } else {
                if ((this.spcoc_cs & 1) != 0) {
                    str = str + "Bypass ";
                }
                if ((this.spcoc_cs & 2) != 0) {
                    str = str + "Reset ";
                }
                if ((this.spcoc_cs & 4) != 0) {
                    str = str + "Terminate ";
                }
                if ((this.spcoc_cs & 8) != 0) {
                    str = str + "Vert_causal ";
                }
                if ((this.spcoc_cs & 16) != 0) {
                    str = str + "Predict ";
                }
                if ((this.spcoc_cs & 32) != 0) {
                    str = str + "Seg_symb ";
                }
            }
            str = ((str + "\n") + " Num. of levels : " + this.spcoc_ndl + "\n") + " Cblk dimension : " + (1 << (this.spcoc_cw + 2)) + "x" + (1 << (this.spcoc_ch + 2)) + "\n";
            switch (this.spcoc_t[0]) {
                case 0:
                    str = str + " Filter         : 9-7 irreversible\n";
                    break;
                case 1:
                    str = str + " Filter         : 5-3 reversible\n";
                    break;
            }
            if (this.spcoc_ps != null) {
                str = str + " Precincts      : ";
                for (int i = 0; i < this.spcoc_ps.length; i++) {
                    str = str + (1 << (this.spcoc_ps[i] & 15)) + "x" + (1 << ((this.spcoc_ps[i] & 240) >> 4)) + " ";
                }
            }
            return str + "\n";
        }
    }

    public class COD implements Cloneable {
        public int lcod;
        public int scod;
        public int sgcod_mct;
        public int sgcod_nl;
        public int sgcod_po;
        public int spcod_ch;
        public int spcod_cs;
        public int spcod_cw;
        public int spcod_ndl;
        public int[] spcod_ps;
        public int[] spcod_t = new int[1];

        public COD getCopy() {
            try {
                return (COD) clone();
            } catch (CloneNotSupportedException e) {
                throw new Error("Cannot clone SIZ marker segment");
            }
        }

        public String toString() {
            boolean z = false;
            String str = ("\n --- COD (" + this.lcod + " bytes) ---\n") + " Coding style   : ";
            if (this.scod == 0) {
                str = str + "Default";
            } else {
                int cb0x;
                int cb0y;
                if ((this.scod & 1) != 0) {
                    str = str + "Precints ";
                }
                if ((this.scod & 2) != 0) {
                    str = str + "SOP ";
                }
                if ((this.scod & 4) != 0) {
                    str = str + "EPH ";
                }
                if ((this.scod & 8) != 0) {
                    cb0x = 1;
                } else {
                    cb0x = 0;
                }
                if ((this.scod & 16) != 0) {
                    cb0y = 1;
                } else {
                    cb0y = 0;
                }
                if (!(cb0x == 0 && cb0y == 0)) {
                    str = (str + "Code-blocks offset") + "\n Cblk partition : " + cb0x + "," + cb0y;
                }
            }
            str = (str + "\n") + " Cblk style     : ";
            if (this.spcod_cs == 0) {
                str = str + "Default";
            } else {
                if ((this.spcod_cs & 1) != 0) {
                    str = str + "Bypass ";
                }
                if ((this.spcod_cs & 2) != 0) {
                    str = str + "Reset ";
                }
                if ((this.spcod_cs & 4) != 0) {
                    str = str + "Terminate ";
                }
                if ((this.spcod_cs & 8) != 0) {
                    str = str + "Vert_causal ";
                }
                if ((this.spcod_cs & 16) != 0) {
                    str = str + "Predict ";
                }
                if ((this.spcod_cs & 32) != 0) {
                    str = str + "Seg_symb ";
                }
            }
            str = (str + "\n") + " Num. of levels : " + this.spcod_ndl + "\n";
            switch (this.sgcod_po) {
                case 0:
                    str = str + " Progress. type : LY_RES_COMP_POS_PROG\n";
                    break;
                case 1:
                    str = str + " Progress. type : RES_LY_COMP_POS_PROG\n";
                    break;
                case 2:
                    str = str + " Progress. type : RES_POS_COMP_LY_PROG\n";
                    break;
                case 3:
                    str = str + " Progress. type : POS_COMP_RES_LY_PROG\n";
                    break;
                case 4:
                    str = str + " Progress. type : COMP_POS_RES_LY_PROG\n";
                    break;
            }
            str = (str + " Num. of layers : " + this.sgcod_nl + "\n") + " Cblk dimension : " + (1 << (this.spcod_cw + 2)) + "x" + (1 << (this.spcod_ch + 2)) + "\n";
            switch (this.spcod_t[0]) {
                case 0:
                    str = str + " Filter         : 9-7 irreversible\n";
                    break;
                case 1:
                    str = str + " Filter         : 5-3 reversible\n";
                    break;
            }
            StringBuilder append = new StringBuilder().append(str).append(" Multi comp tr. : ");
            if (this.sgcod_mct == 1) {
                z = true;
            }
            str = append.append(z).append("\n").toString();
            if (this.spcod_ps != null) {
                str = str + " Precincts      : ";
                for (int i = 0; i < this.spcod_ps.length; i++) {
                    str = str + (1 << (this.spcod_ps[i] & 15)) + "x" + (1 << ((this.spcod_ps[i] & 240) >> 4)) + " ";
                }
            }
            return str + "\n";
        }
    }

    public class COM {
        public byte[] ccom;
        public int lcom;
        public int rcom;

        public String toString() {
            String str = "\n --- COM (" + this.lcom + " bytes) ---\n";
            if (this.rcom == 0) {
                str = str + " Registration : General use (binary values)\n";
            } else if (this.rcom == 1) {
                str = (str + " Registration : General use (IS 8859-15:1999 (Latin) values)\n") + " Text         : " + new String(this.ccom) + "\n";
            } else {
                str = str + " Registration : Unknown\n";
            }
            return str + "\n";
        }
    }

    public class CRG {
        public int lcrg;
        public int[] xcrg;
        public int[] ycrg;

        public String toString() {
            String str = "\n --- CRG (" + this.lcrg + " bytes) ---\n";
            for (int c = 0; c < this.xcrg.length; c++) {
                str = str + " Component " + c + " offset : " + this.xcrg[c] + "," + this.ycrg[c] + "\n";
            }
            return str + "\n";
        }
    }

    public class POC {
        public int[] cepoc;
        public int[] cspoc;
        public int lpoc;
        public int[] lyepoc;
        public int[] ppoc;
        public int[] repoc;
        public int[] rspoc;

        public String toString() {
            String str = ("\n --- POC (" + this.lpoc + " bytes) ---\n") + " Chg_idx RSpoc CSpoc LYEpoc REpoc CEpoc Ppoc\n";
            for (int chg = 0; chg < this.rspoc.length; chg++) {
                str = str + "   " + chg + "      " + this.rspoc[chg] + "     " + this.cspoc[chg] + "     " + this.lyepoc[chg] + "      " + this.repoc[chg] + "     " + this.cepoc[chg];
                switch (this.ppoc[chg]) {
                    case 0:
                        str = str + "  LY_RES_COMP_POS_PROG\n";
                        break;
                    case 1:
                        str = str + "  RES_LY_COMP_POS_PROG\n";
                        break;
                    case 2:
                        str = str + "  RES_POS_COMP_LY_PROG\n";
                        break;
                    case 3:
                        str = str + "  POS_COMP_RES_LY_PROG\n";
                        break;
                    case 4:
                        str = str + "  COMP_POS_RES_LY_PROG\n";
                        break;
                    default:
                        break;
                }
            }
            return str + "\n";
        }
    }

    public class QCC {
        public int cqcc;
        private int gb = -1;
        public int lqcc;
        private int qType = -1;
        public int[][] spqcc;
        public int sqcc;

        public int getQuantType() {
            if (this.qType == -1) {
                this.qType = this.sqcc & -225;
            }
            return this.qType;
        }

        public int getNumGuardBits() {
            if (this.gb == -1) {
                this.gb = (this.sqcc >> 5) & 7;
            }
            return this.gb;
        }

        public String toString() {
            String str = (("\n --- QCC (" + this.lqcc + " bytes) ---\n") + " Component      : " + this.cqcc + "\n") + " Quant. type    : ";
            int qt = getQuantType();
            if (qt == 0) {
                str = str + "No quantization \n";
            } else if (qt == 1) {
                str = str + "Scalar derived\n";
            } else if (qt == 2) {
                str = str + "Scalar expounded\n";
            }
            str = str + " Guard bits     : " + getNumGuardBits() + "\n";
            int i;
            int j;
            if (qt == 0) {
                str = str + " Exponents   :\n";
                for (i = 0; i < this.spqcc.length; i++) {
                    j = 0;
                    while (j < this.spqcc[i].length) {
                        if (i == 0 && j == 0) {
                            str = str + "\tr=0 : " + ((this.spqcc[0][0] >> 3) & 31) + "\n";
                        } else if (i != 0 && j > 0) {
                            str = str + "\tr=" + i + ",s=" + j + " : " + ((this.spqcc[i][j] >> 3) & 31) + "\n";
                        }
                        j++;
                    }
                }
            } else {
                str = str + " Exp / Mantissa : \n";
                for (i = 0; i < this.spqcc.length; i++) {
                    j = 0;
                    while (j < this.spqcc[i].length) {
                        int exp;
                        if (i == 0 && j == 0) {
                            exp = (this.spqcc[0][0] >> 11) & 31;
                            str = str + "\tr=0 : " + exp + " / " + ((double) ((-1.0f - (((float) (this.spqcc[0][0] & 2047)) / 2048.0f)) / ((float) (-1 << exp)))) + "\n";
                        } else if (i != 0 && j > 0) {
                            exp = (this.spqcc[i][j] >> 11) & 31;
                            str = str + "\tr=" + i + ",s=" + j + " : " + exp + " / " + ((double) ((-1.0f - (((float) (this.spqcc[i][j] & 2047)) / 2048.0f)) / ((float) (-1 << exp)))) + "\n";
                        }
                        j++;
                    }
                }
            }
            return str + "\n";
        }
    }

    public class QCD {
        private int gb = -1;
        public int lqcd;
        private int qType = -1;
        public int[][] spqcd;
        public int sqcd;

        public int getQuantType() {
            if (this.qType == -1) {
                this.qType = this.sqcd & -225;
            }
            return this.qType;
        }

        public int getNumGuardBits() {
            if (this.gb == -1) {
                this.gb = (this.sqcd >> 5) & 7;
            }
            return this.gb;
        }

        public String toString() {
            String str = ("\n --- QCD (" + this.lqcd + " bytes) ---\n") + " Quant. type    : ";
            int qt = getQuantType();
            if (qt == 0) {
                str = str + "No quantization \n";
            } else if (qt == 1) {
                str = str + "Scalar derived\n";
            } else if (qt == 2) {
                str = str + "Scalar expounded\n";
            }
            str = str + " Guard bits     : " + getNumGuardBits() + "\n";
            int i;
            int j;
            if (qt == 0) {
                str = str + " Exponents   :\n";
                for (i = 0; i < this.spqcd.length; i++) {
                    j = 0;
                    while (j < this.spqcd[i].length) {
                        if (i == 0 && j == 0) {
                            str = str + "\tr=0 : " + ((this.spqcd[0][0] >> 3) & 31) + "\n";
                        } else if (i != 0 && j > 0) {
                            str = str + "\tr=" + i + ",s=" + j + " : " + ((this.spqcd[i][j] >> 3) & 31) + "\n";
                        }
                        j++;
                    }
                }
            } else {
                str = str + " Exp / Mantissa : \n";
                for (i = 0; i < this.spqcd.length; i++) {
                    j = 0;
                    while (j < this.spqcd[i].length) {
                        int exp;
                        if (i == 0 && j == 0) {
                            exp = (this.spqcd[0][0] >> 11) & 31;
                            str = str + "\tr=0 : " + exp + " / " + ((double) ((-1.0f - (((float) (this.spqcd[0][0] & 2047)) / 2048.0f)) / ((float) (-1 << exp)))) + "\n";
                        } else if (i != 0 && j > 0) {
                            exp = (this.spqcd[i][j] >> 11) & 31;
                            str = str + "\tr=" + i + ",s=" + j + " : " + exp + " / " + ((double) ((-1.0f - (((float) (this.spqcd[i][j] & 2047)) / 2048.0f)) / ((float) (-1 << exp)))) + "\n";
                        }
                        j++;
                    }
                }
            }
            return str + "\n";
        }
    }

    public class RGN {
        public int crgn;
        public int lrgn;
        public int sprgn;
        public int srgn;

        public String toString() {
            String str = ("\n --- RGN (" + this.lrgn + " bytes) ---\n") + " Component : " + this.crgn + "\n";
            if (this.srgn == 0) {
                str = str + " ROI style : Implicit\n";
            } else {
                str = str + " ROI style : Unsupported\n";
            }
            return (str + " ROI shift : " + this.sprgn + "\n") + "\n";
        }
    }

    public class SIZ implements Cloneable {
        private int[] compHeight = null;
        private int[] compWidth = null;
        public int csiz;
        public int lsiz;
        private int maxCompHeight = -1;
        private int maxCompWidth = -1;
        private int numTiles = -1;
        private int[] origBitDepth = null;
        private boolean[] origSigned = null;
        public int rsiz;
        public int[] ssiz;
        public int x0siz;
        public int[] xrsiz;
        public int xsiz;
        public int xt0siz;
        public int xtsiz;
        public int y0siz;
        public int[] yrsiz;
        public int ysiz;
        public int yt0siz;
        public int ytsiz;

        public int getCompImgWidth(int c) {
            if (this.compWidth == null) {
                this.compWidth = new int[this.csiz];
                for (int cc = 0; cc < this.csiz; cc++) {
                    this.compWidth[cc] = (int) (Math.ceil(((double) this.xsiz) / ((double) this.xrsiz[cc])) - Math.ceil(((double) this.x0siz) / ((double) this.xrsiz[cc])));
                }
            }
            return this.compWidth[c];
        }

        public int getMaxCompWidth() {
            if (this.compWidth == null) {
                this.compWidth = new int[this.csiz];
                for (int cc = 0; cc < this.csiz; cc++) {
                    this.compWidth[cc] = (int) (Math.ceil(((double) this.xsiz) / ((double) this.xrsiz[cc])) - Math.ceil(((double) this.x0siz) / ((double) this.xrsiz[cc])));
                }
            }
            if (this.maxCompWidth == -1) {
                for (int c = 0; c < this.csiz; c++) {
                    if (this.compWidth[c] > this.maxCompWidth) {
                        this.maxCompWidth = this.compWidth[c];
                    }
                }
            }
            return this.maxCompWidth;
        }

        public int getCompImgHeight(int c) {
            if (this.compHeight == null) {
                this.compHeight = new int[this.csiz];
                for (int cc = 0; cc < this.csiz; cc++) {
                    this.compHeight[cc] = (int) (Math.ceil(((double) this.ysiz) / ((double) this.yrsiz[cc])) - Math.ceil(((double) this.y0siz) / ((double) this.yrsiz[cc])));
                }
            }
            return this.compHeight[c];
        }

        public int getMaxCompHeight() {
            if (this.compHeight == null) {
                this.compHeight = new int[this.csiz];
                for (int cc = 0; cc < this.csiz; cc++) {
                    this.compHeight[cc] = (int) (Math.ceil(((double) this.ysiz) / ((double) this.yrsiz[cc])) - Math.ceil(((double) this.y0siz) / ((double) this.yrsiz[cc])));
                }
            }
            if (this.maxCompHeight == -1) {
                for (int c = 0; c < this.csiz; c++) {
                    if (this.compHeight[c] != this.maxCompHeight) {
                        this.maxCompHeight = this.compHeight[c];
                    }
                }
            }
            return this.maxCompHeight;
        }

        public int getNumTiles() {
            if (this.numTiles == -1) {
                this.numTiles = ((((this.xsiz - this.xt0siz) + this.xtsiz) - 1) / this.xtsiz) * ((((this.ysiz - this.yt0siz) + this.ytsiz) - 1) / this.ytsiz);
            }
            return this.numTiles;
        }

        public boolean isOrigSigned(int c) {
            if (this.origSigned == null) {
                this.origSigned = new boolean[this.csiz];
                for (int cc = 0; cc < this.csiz; cc++) {
                    this.origSigned[cc] = (this.ssiz[cc] >>> 7) == 1;
                }
            }
            return this.origSigned[c];
        }

        public int getOrigBitDepth(int c) {
            if (this.origBitDepth == null) {
                this.origBitDepth = new int[this.csiz];
                for (int cc = 0; cc < this.csiz; cc++) {
                    this.origBitDepth[cc] = (this.ssiz[cc] & CertificateBody.profileType) + 1;
                }
            }
            return this.origBitDepth[c];
        }

        public SIZ getCopy() {
            try {
                return (SIZ) clone();
            } catch (CloneNotSupportedException e) {
                throw new Error("Cannot clone SIZ marker segment");
            }
        }

        public String toString() {
            int i;
            String str = ((((("\n --- SIZ (" + this.lsiz + " bytes) ---\n") + " Capabilities : " + this.rsiz + "\n") + " Image dim.   : " + (this.xsiz - this.x0siz) + "x" + (this.ysiz - this.y0siz) + ", (off=" + this.x0siz + "," + this.y0siz + ")\n") + " Tile dim.    : " + this.xtsiz + "x" + this.ytsiz + ", (off=" + this.xt0siz + "," + this.yt0siz + ")\n") + " Component(s) : " + this.csiz + "\n") + " Orig. depth  : ";
            for (i = 0; i < this.csiz; i++) {
                str = str + getOrigBitDepth(i) + " ";
            }
            str = (str + "\n") + " Orig. signed : ";
            for (i = 0; i < this.csiz; i++) {
                str = str + isOrigSigned(i) + " ";
            }
            str = (str + "\n") + " Subs. factor : ";
            for (i = 0; i < this.csiz; i++) {
                str = str + this.xrsiz[i] + "," + this.yrsiz[i] + " ";
            }
            return str + "\n";
        }
    }

    public class SOT {
        public int isot;
        public int lsot;
        public int psot;
        public int tnsot;
        public int tpsot;

        public String toString() {
            return ((((("\n --- SOT (" + this.lsot + " bytes) ---\n") + "Tile index         : " + this.isot + "\n") + "Tile-part length   : " + this.psot + " bytes\n") + "Tile-part index    : " + this.tpsot + "\n") + "Num. of tile-parts : " + this.tnsot + "\n") + "\n";
        }
    }

    public SIZ getNewSIZ() {
        return new SIZ();
    }

    public SOT getNewSOT() {
        return new SOT();
    }

    public COD getNewCOD() {
        return new COD();
    }

    public COC getNewCOC() {
        return new COC();
    }

    public RGN getNewRGN() {
        return new RGN();
    }

    public QCD getNewQCD() {
        return new QCD();
    }

    public QCC getNewQCC() {
        return new QCC();
    }

    public POC getNewPOC() {
        return new POC();
    }

    public CRG getNewCRG() {
        return new CRG();
    }

    public COM getNewCOM() {
        this.ncom++;
        return new COM();
    }

    public int getNumCOM() {
        return this.ncom;
    }

    public String toStringMainHeader() {
        int c;
        int nc = this.siz.csiz;
        String str = "" + this.siz;
        if (this.cod.get("main") != null) {
            str = str + "" + ((COD) this.cod.get("main"));
        }
        for (c = 0; c < nc; c++) {
            if (this.coc.get("main_c" + c) != null) {
                str = str + "" + ((COC) this.coc.get("main_c" + c));
            }
        }
        if (this.qcd.get("main") != null) {
            str = str + "" + ((QCD) this.qcd.get("main"));
        }
        for (c = 0; c < nc; c++) {
            if (this.qcc.get("main_c" + c) != null) {
                str = str + "" + ((QCC) this.qcc.get("main_c" + c));
            }
        }
        for (c = 0; c < nc; c++) {
            if (this.rgn.get("main_c" + c) != null) {
                str = str + "" + ((RGN) this.rgn.get("main_c" + c));
            }
        }
        if (this.poc.get("main") != null) {
            str = str + "" + ((POC) this.poc.get("main"));
        }
        if (this.crg != null) {
            str = str + "" + this.crg;
        }
        for (int i = 0; i < this.ncom; i++) {
            if (this.com.get("main_" + i) != null) {
                str = str + "" + ((COM) this.com.get("main_" + i));
            }
        }
        return str;
    }

    public String toStringTileHeader(int t, int ntp) {
        int c;
        int nc = this.siz.csiz;
        String str = "";
        for (int i = 0; i < ntp; i++) {
            str = (str + "Tile-part " + i + ", tile " + t + ":\n") + "" + ((SOT) this.sot.get("t" + t + "_tp" + i));
        }
        if (this.cod.get("t" + t) != null) {
            str = str + "" + ((COD) this.cod.get("t" + t));
        }
        for (c = 0; c < nc; c++) {
            if (this.coc.get("t" + t + "_c" + c) != null) {
                str = str + "" + ((COC) this.coc.get("t" + t + "_c" + c));
            }
        }
        if (this.qcd.get("t" + t) != null) {
            str = str + "" + ((QCD) this.qcd.get("t" + t));
        }
        for (c = 0; c < nc; c++) {
            if (this.qcc.get("t" + t + "_c" + c) != null) {
                str = str + "" + ((QCC) this.qcc.get("t" + t + "_c" + c));
            }
        }
        for (c = 0; c < nc; c++) {
            if (this.rgn.get("t" + t + "_c" + c) != null) {
                str = str + "" + ((RGN) this.rgn.get("t" + t + "_c" + c));
            }
        }
        if (this.poc.get("t" + t) != null) {
            return str + "" + ((POC) this.poc.get("t" + t));
        }
        return str;
    }

    public String toStringThNoSOT(int t, int ntp) {
        int c;
        int nc = this.siz.csiz;
        String str = "";
        if (this.cod.get("t" + t) != null) {
            str = str + "" + ((COD) this.cod.get("t" + t));
        }
        for (c = 0; c < nc; c++) {
            if (this.coc.get("t" + t + "_c" + c) != null) {
                str = str + "" + ((COC) this.coc.get("t" + t + "_c" + c));
            }
        }
        if (this.qcd.get("t" + t) != null) {
            str = str + "" + ((QCD) this.qcd.get("t" + t));
        }
        for (c = 0; c < nc; c++) {
            if (this.qcc.get("t" + t + "_c" + c) != null) {
                str = str + "" + ((QCC) this.qcc.get("t" + t + "_c" + c));
            }
        }
        for (c = 0; c < nc; c++) {
            if (this.rgn.get("t" + t + "_c" + c) != null) {
                str = str + "" + ((RGN) this.rgn.get("t" + t + "_c" + c));
            }
        }
        if (this.poc.get("t" + t) != null) {
            return str + "" + ((POC) this.poc.get("t" + t));
        }
        return str;
    }

    public HeaderInfo getCopy(int nt) {
        try {
            HeaderInfo nhi = (HeaderInfo) clone();
            nhi.siz = this.siz.getCopy();
            if (this.cod.get("main") != null) {
                nhi.cod.put("main", ((COD) this.cod.get("main")).getCopy());
            }
            for (int t = 0; t < nt; t++) {
                if (this.cod.get("t" + t) != null) {
                    nhi.cod.put("t" + t, ((COD) this.cod.get("t" + t)).getCopy());
                }
            }
            return nhi;
        } catch (CloneNotSupportedException e) {
            throw new Error("Cannot clone HeaderInfo instance");
        }
    }
}
