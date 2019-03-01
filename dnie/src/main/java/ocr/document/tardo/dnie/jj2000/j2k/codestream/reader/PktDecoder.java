package jj2000.j2k.codestream.reader;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Vector;
import jj2000.j2k.codestream.CBlkCoordInfo;
import jj2000.j2k.codestream.Markers;
import jj2000.j2k.codestream.PrecInfo;
import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.entropy.StdEntropyCoderOptions;
import jj2000.j2k.image.Coord;
import jj2000.j2k.io.RandomAccessIO;
import jj2000.j2k.util.ArrayUtil;
import jj2000.j2k.util.MathUtil;
import jj2000.j2k.wavelet.synthesis.SubbandSyn;

public class PktDecoder implements StdEntropyCoderOptions {
    private final int INIT_LBLOCK = 3;
    private PktHeaderBitReader bin;
    private int cQuit;
    private Vector[] cblks;
    private DecoderSpecs decSpec;
    private RandomAccessIO ehs;
    private boolean ephUsed = false;
    private HeaderDecoder hd;
    private boolean isTruncMode;
    private int[][][][][] lblock;
    private int maxCB;
    private int nc;
    private int ncb;
    private boolean ncbQuit;
    private int nl = 0;
    private Coord[][] numPrec;
    private int pktIdx;
    private boolean pph = false;
    private ByteArrayInputStream pphbais;
    private PrecInfo[][][] ppinfo;
    private int rQuit;
    private int sQuit;
    private boolean sopUsed = false;
    private BitstreamReaderAgent src;
    private int tIdx;
    private int tQuit;
    private TagTreeDecoder[][][][] ttIncl;
    private TagTreeDecoder[][][][] ttMaxBP;
    private int xQuit;
    private int yQuit;

    public PktDecoder(DecoderSpecs decSpec, HeaderDecoder hd, RandomAccessIO ehs, BitstreamReaderAgent src, boolean isTruncMode, int maxCB) {
        this.decSpec = decSpec;
        this.hd = hd;
        this.ehs = ehs;
        this.isTruncMode = isTruncMode;
        this.bin = new PktHeaderBitReader(ehs);
        this.src = src;
        this.ncb = 0;
        this.ncbQuit = false;
        this.maxCB = maxCB;
    }

    public CBlkInfo[][][][][] restart(int nc, int[] mdl, int nl, CBlkInfo[][][][][] cbI, boolean pph, ByteArrayInputStream pphbais) {
        this.nc = nc;
        this.nl = nl;
        this.tIdx = this.src.getTileIdx();
        this.pph = pph;
        this.pphbais = pphbais;
        this.sopUsed = ((Boolean) this.decSpec.sops.getTileDef(this.tIdx)).booleanValue();
        this.pktIdx = 0;
        this.ephUsed = ((Boolean) this.decSpec.ephs.getTileDef(this.tIdx)).booleanValue();
        cbI = new CBlkInfo[nc][][][][];
        this.lblock = new int[nc][][][][];
        this.ttIncl = new TagTreeDecoder[nc][][][];
        this.ttMaxBP = new TagTreeDecoder[nc][][][];
        this.numPrec = new Coord[nc][];
        this.ppinfo = new PrecInfo[nc][][];
        int cb0x = this.src.getCbULX();
        int cb0y = this.src.getCbULY();
        for (int c = 0; c < nc; c++) {
            cbI[c] = new CBlkInfo[(mdl[c] + 1)][][][];
            this.lblock[c] = new int[(mdl[c] + 1)][][][];
            this.ttIncl[c] = new TagTreeDecoder[(mdl[c] + 1)][][];
            this.ttMaxBP[c] = new TagTreeDecoder[(mdl[c] + 1)][][];
            this.numPrec[c] = new Coord[(mdl[c] + 1)];
            this.ppinfo[c] = new PrecInfo[(mdl[c] + 1)][];
            int tcx0 = this.src.getResULX(c, mdl[c]);
            int tcy0 = this.src.getResULY(c, mdl[c]);
            int tcx1 = tcx0 + this.src.getTileCompWidth(this.tIdx, c, mdl[c]);
            int tcy1 = tcy0 + this.src.getTileCompHeight(this.tIdx, c, mdl[c]);
            int r = 0;
            while (r <= mdl[c]) {
                int trx0 = (int) Math.ceil(((double) tcx0) / ((double) (1 << (mdl[c] - r))));
                int try0 = (int) Math.ceil(((double) tcy0) / ((double) (1 << (mdl[c] - r))));
                int trx1 = (int) Math.ceil(((double) tcx1) / ((double) (1 << (mdl[c] - r))));
                int try1 = (int) Math.ceil(((double) tcy1) / ((double) (1 << (mdl[c] - r))));
                double twoppx = (double) getPPX(this.tIdx, c, r);
                double twoppy = (double) getPPY(this.tIdx, c, r);
                this.numPrec[c][r] = new Coord();
                if (trx1 > trx0) {
                    this.numPrec[c][r].f36x = ((int) Math.ceil(((double) (trx1 - cb0x)) / twoppx)) - ((int) Math.floor(((double) (trx0 - cb0x)) / twoppx));
                } else {
                    this.numPrec[c][r].f36x = 0;
                }
                if (try1 > try0) {
                    this.numPrec[c][r].f37y = ((int) Math.ceil(((double) (try1 - cb0y)) / twoppy)) - ((int) Math.floor(((double) (try0 - cb0y)) / twoppy));
                } else {
                    this.numPrec[c][r].f37y = 0;
                }
                int mins = r == 0 ? 0 : 1;
                int maxs = r == 0 ? 1 : 4;
                int maxPrec = this.numPrec[c][r].f36x * this.numPrec[c][r].f37y;
                this.ttIncl[c][r] = (TagTreeDecoder[][]) Array.newInstance(TagTreeDecoder.class, new int[]{maxPrec, maxs + 1});
                this.ttMaxBP[c][r] = (TagTreeDecoder[][]) Array.newInstance(TagTreeDecoder.class, new int[]{maxPrec, maxs + 1});
                cbI[c][r] = new CBlkInfo[(maxs + 1)][][];
                this.lblock[c][r] = new int[(maxs + 1)][][];
                this.ppinfo[c][r] = new PrecInfo[maxPrec];
                fillPrecInfo(c, r, mdl[c]);
                SubbandSyn root = this.src.getSynSubbandTree(this.tIdx, c);
                for (int s = mins; s < maxs; s++) {
                    Coord nBlk = ((SubbandSyn) root.getSubbandByIdx(r, s)).numCb;
                    cbI[c][r][s] = (CBlkInfo[][]) Array.newInstance(CBlkInfo.class, new int[]{nBlk.f37y, nBlk.f36x});
                    this.lblock[c][r][s] = (int[][]) Array.newInstance(Integer.TYPE, new int[]{nBlk.f37y, nBlk.f36x});
                    for (int i = nBlk.f37y - 1; i >= 0; i--) {
                        ArrayUtil.intArraySet(this.lblock[c][r][s][i], 3);
                    }
                }
                r++;
            }
        }
        return cbI;
    }

    private void fillPrecInfo(int c, int r, int mdl) {
        if (this.ppinfo[c][r].length != 0) {
            Coord tileI = this.src.getTile(null);
            Coord nTiles = this.src.getNumTiles(null);
            int xt0siz = this.src.getTilePartULX();
            int yt0siz = this.src.getTilePartULY();
            int xtsiz = this.src.getNomTileWidth();
            int ytsiz = this.src.getNomTileHeight();
            int x0siz = this.hd.getImgULX();
            int y0siz = this.hd.getImgULY();
            int xsiz = this.hd.getImgWidth();
            int ysiz = this.hd.getImgHeight();
            int tx0 = tileI.f36x == 0 ? x0siz : xt0siz + (tileI.f36x * xtsiz);
            int ty0 = tileI.f37y == 0 ? y0siz : yt0siz + (tileI.f37y * ytsiz);
            int tx1;
            if (tileI.f36x != nTiles.f36x - 1) {
                tx1 = xt0siz + ((tileI.f36x + 1) * xtsiz);
            } else {
                tx1 = xsiz;
            }
            int ty1;
            if (tileI.f37y != nTiles.f37y - 1) {
                ty1 = yt0siz + ((tileI.f37y + 1) * ytsiz);
            } else {
                ty1 = ysiz;
            }
            int xrsiz = this.hd.getCompSubsX(c);
            int yrsiz = this.hd.getCompSubsY(c);
            int tcx0 = this.src.getResULX(c, mdl);
            int tcy0 = this.src.getResULY(c, mdl);
            int ndl = mdl - r;
            int trx0 = (int) Math.ceil(((double) tcx0) / ((double) (1 << ndl)));
            int try0 = (int) Math.ceil(((double) tcy0) / ((double) (1 << ndl)));
            int trx1 = (int) Math.ceil(((double) (tcx0 + this.src.getTileCompWidth(this.tIdx, c, mdl))) / ((double) (1 << ndl)));
            int try1 = (int) Math.ceil(((double) (tcy0 + this.src.getTileCompHeight(this.tIdx, c, mdl))) / ((double) (1 << ndl)));
            int cb0x = this.src.getCbULX();
            int cb0y = this.src.getCbULY();
            double twoppx = (double) getPPX(this.tIdx, c, r);
            double twoppy = (double) getPPY(this.tIdx, c, r);
            int twoppx2 = (int) (twoppx / 2.0d);
            int twoppy2 = (int) (twoppy / 2.0d);
            int maxPrec = this.ppinfo[c][r].length;
            int nPrec = 0;
            int istart = (int) Math.floor(((double) (try0 - cb0y)) / twoppy);
            int iend = (int) Math.floor(((double) ((try1 - 1) - cb0y)) / twoppy);
            int jstart = (int) Math.floor(((double) (trx0 - cb0x)) / twoppx);
            int jend = (int) Math.floor(((double) ((trx1 - 1) - cb0x)) / twoppx);
            SubbandSyn root = this.src.getSynSubbandTree(this.tIdx, c);
            int prg_w = ((int) twoppx) << ndl;
            int prg_h = ((int) twoppy) << ndl;
            for (int i = istart; i <= iend; i++) {
                int j = jstart;
                while (j <= jend) {
                    int prg_ulx;
                    int prg_uly;
                    if (j != jstart || (trx0 - cb0x) % (((int) twoppx) * xrsiz) == 0) {
                        prg_ulx = cb0x + ((j * xrsiz) * (((int) twoppx) << ndl));
                    } else {
                        prg_ulx = tx0;
                    }
                    if (i != istart || (try0 - cb0y) % (((int) twoppy) * yrsiz) == 0) {
                        prg_uly = cb0y + ((i * yrsiz) * (((int) twoppy) << ndl));
                    } else {
                        prg_uly = ty0;
                    }
                    this.ppinfo[c][r][nPrec] = new PrecInfo(r, (int) (((double) cb0x) + (((double) j) * twoppx)), (int) (((double) cb0y) + (((double) i) * twoppy)), (int) twoppx, (int) twoppy, prg_ulx, prg_uly, prg_w, prg_h);
                    int acb0x;
                    int acb0y;
                    int p0x;
                    int p1x;
                    int p0y;
                    int p1y;
                    SubbandSyn sb;
                    int s0x;
                    int s1x;
                    int s0y;
                    int s1y;
                    int cw;
                    int ch;
                    int k0;
                    int kstart;
                    int kend;
                    int l0;
                    int lstart;
                    int lend;
                    int k;
                    int l;
                    CBlkCoordInfo cBlkCoordInfo;
                    int tmp1;
                    int tmp2;
                    if (r == 0) {
                        acb0x = cb0x;
                        acb0y = cb0y;
                        p0x = acb0x + (((int) twoppx) * j);
                        p1x = p0x + ((int) twoppx);
                        p0y = acb0y + (((int) twoppy) * i);
                        p1y = p0y + ((int) twoppy);
                        sb = (SubbandSyn) root.getSubbandByIdx(0, 0);
                        if (p0x < sb.ulcx) {
                            s0x = sb.ulcx;
                        } else {
                            s0x = p0x;
                        }
                        if (p1x > sb.ulcx + sb.w) {
                            s1x = sb.ulcx + sb.w;
                        } else {
                            s1x = p1x;
                        }
                        if (p0y < sb.ulcy) {
                            s0y = sb.ulcy;
                        } else {
                            s0y = p0y;
                        }
                        if (p1y > sb.ulcy + sb.h) {
                            s1y = sb.ulcy + sb.h;
                        } else {
                            s1y = p1y;
                        }
                        cw = sb.nomCBlkW;
                        ch = sb.nomCBlkH;
                        k0 = (int) Math.floor(((double) (sb.ulcy - acb0y)) / ((double) ch));
                        kstart = (int) Math.floor(((double) (s0y - acb0y)) / ((double) ch));
                        kend = (int) Math.floor(((double) ((s1y - 1) - acb0y)) / ((double) ch));
                        l0 = (int) Math.floor(((double) (sb.ulcx - acb0x)) / ((double) cw));
                        lstart = (int) Math.floor(((double) (s0x - acb0x)) / ((double) cw));
                        lend = (int) Math.floor(((double) ((s1x - 1) - acb0x)) / ((double) cw));
                        if (s1x - s0x <= 0 || s1y - s0y <= 0) {
                            this.ppinfo[c][r][nPrec].nblk[0] = 0;
                            this.ttIncl[c][r][nPrec][0] = new TagTreeDecoder(0, 0);
                            this.ttMaxBP[c][r][nPrec][0] = new TagTreeDecoder(0, 0);
                        } else {
                            this.ttIncl[c][r][nPrec][0] = new TagTreeDecoder((kend - kstart) + 1, (lend - lstart) + 1);
                            this.ttMaxBP[c][r][nPrec][0] = new TagTreeDecoder((kend - kstart) + 1, (lend - lstart) + 1);
                            this.ppinfo[c][r][nPrec].cblk[0] = (CBlkCoordInfo[][]) Array.newInstance(CBlkCoordInfo.class, new int[]{(kend - kstart) + 1, (lend - lstart) + 1});
                            this.ppinfo[c][r][nPrec].nblk[0] = ((kend - kstart) + 1) * ((lend - lstart) + 1);
                            for (k = kstart; k <= kend; k++) {
                                for (l = lstart; l <= lend; l++) {
                                    cBlkCoordInfo = new CBlkCoordInfo(k - k0, l - l0);
                                    if (l == l0) {
                                        cBlkCoordInfo.ulx = sb.ulx;
                                    } else {
                                        cBlkCoordInfo.ulx = (sb.ulx + (l * cw)) - (sb.ulcx - acb0x);
                                    }
                                    if (k == k0) {
                                        cBlkCoordInfo.uly = sb.uly;
                                    } else {
                                        cBlkCoordInfo.uly = (sb.uly + (k * ch)) - (sb.ulcy - acb0y);
                                    }
                                    tmp1 = acb0x + (l * cw);
                                    if (tmp1 <= sb.ulcx) {
                                        tmp1 = sb.ulcx;
                                    }
                                    tmp2 = acb0x + ((l + 1) * cw);
                                    if (tmp2 > sb.ulcx + sb.w) {
                                        tmp2 = sb.ulcx + sb.w;
                                    }
                                    cBlkCoordInfo.w = tmp2 - tmp1;
                                    tmp1 = acb0y + (k * ch);
                                    if (tmp1 <= sb.ulcy) {
                                        tmp1 = sb.ulcy;
                                    }
                                    tmp2 = acb0y + ((k + 1) * ch);
                                    if (tmp2 > sb.ulcy + sb.h) {
                                        tmp2 = sb.ulcy + sb.h;
                                    }
                                    cBlkCoordInfo.h = tmp2 - tmp1;
                                    this.ppinfo[c][r][nPrec].cblk[0][k - kstart][l - lstart] = cBlkCoordInfo;
                                }
                            }
                        }
                    } else {
                        acb0y = cb0y;
                        p0x = 0 + (j * twoppx2);
                        p1x = p0x + twoppx2;
                        p0y = acb0y + (i * twoppy2);
                        p1y = p0y + twoppy2;
                        sb = (SubbandSyn) root.getSubbandByIdx(r, 1);
                        if (p0x < sb.ulcx) {
                            s0x = sb.ulcx;
                        } else {
                            s0x = p0x;
                        }
                        if (p1x > sb.ulcx + sb.w) {
                            s1x = sb.ulcx + sb.w;
                        } else {
                            s1x = p1x;
                        }
                        if (p0y < sb.ulcy) {
                            s0y = sb.ulcy;
                        } else {
                            s0y = p0y;
                        }
                        if (p1y > sb.ulcy + sb.h) {
                            s1y = sb.ulcy + sb.h;
                        } else {
                            s1y = p1y;
                        }
                        cw = sb.nomCBlkW;
                        ch = sb.nomCBlkH;
                        k0 = (int) Math.floor(((double) (sb.ulcy - acb0y)) / ((double) ch));
                        kstart = (int) Math.floor(((double) (s0y - acb0y)) / ((double) ch));
                        kend = (int) Math.floor(((double) ((s1y - 1) - acb0y)) / ((double) ch));
                        l0 = (int) Math.floor(((double) (sb.ulcx - 0)) / ((double) cw));
                        lstart = (int) Math.floor(((double) (s0x - 0)) / ((double) cw));
                        lend = (int) Math.floor(((double) ((s1x - 1) - 0)) / ((double) cw));
                        if (s1x - s0x <= 0 || s1y - s0y <= 0) {
                            this.ppinfo[c][r][nPrec].nblk[1] = 0;
                            this.ttIncl[c][r][nPrec][1] = new TagTreeDecoder(0, 0);
                            this.ttMaxBP[c][r][nPrec][1] = new TagTreeDecoder(0, 0);
                        } else {
                            this.ttIncl[c][r][nPrec][1] = new TagTreeDecoder((kend - kstart) + 1, (lend - lstart) + 1);
                            this.ttMaxBP[c][r][nPrec][1] = new TagTreeDecoder((kend - kstart) + 1, (lend - lstart) + 1);
                            this.ppinfo[c][r][nPrec].cblk[1] = (CBlkCoordInfo[][]) Array.newInstance(CBlkCoordInfo.class, new int[]{(kend - kstart) + 1, (lend - lstart) + 1});
                            this.ppinfo[c][r][nPrec].nblk[1] = ((kend - kstart) + 1) * ((lend - lstart) + 1);
                            for (k = kstart; k <= kend; k++) {
                                for (l = lstart; l <= lend; l++) {
                                    cBlkCoordInfo = new CBlkCoordInfo(k - k0, l - l0);
                                    if (l == l0) {
                                        cBlkCoordInfo.ulx = sb.ulx;
                                    } else {
                                        cBlkCoordInfo.ulx = (sb.ulx + (l * cw)) - (sb.ulcx - 0);
                                    }
                                    if (k == k0) {
                                        cBlkCoordInfo.uly = sb.uly;
                                    } else {
                                        cBlkCoordInfo.uly = (sb.uly + (k * ch)) - (sb.ulcy - acb0y);
                                    }
                                    tmp1 = 0 + (l * cw);
                                    if (tmp1 <= sb.ulcx) {
                                        tmp1 = sb.ulcx;
                                    }
                                    tmp2 = 0 + ((l + 1) * cw);
                                    if (tmp2 > sb.ulcx + sb.w) {
                                        tmp2 = sb.ulcx + sb.w;
                                    }
                                    cBlkCoordInfo.w = tmp2 - tmp1;
                                    tmp1 = acb0y + (k * ch);
                                    if (tmp1 <= sb.ulcy) {
                                        tmp1 = sb.ulcy;
                                    }
                                    tmp2 = acb0y + ((k + 1) * ch);
                                    if (tmp2 > sb.ulcy + sb.h) {
                                        tmp2 = sb.ulcy + sb.h;
                                    }
                                    cBlkCoordInfo.h = tmp2 - tmp1;
                                    this.ppinfo[c][r][nPrec].cblk[1][k - kstart][l - lstart] = cBlkCoordInfo;
                                }
                            }
                        }
                        acb0x = cb0x;
                        p0x = acb0x + (j * twoppx2);
                        p1x = p0x + twoppx2;
                        p0y = 0 + (i * twoppy2);
                        p1y = p0y + twoppy2;
                        sb = (SubbandSyn) root.getSubbandByIdx(r, 2);
                        if (p0x < sb.ulcx) {
                            s0x = sb.ulcx;
                        } else {
                            s0x = p0x;
                        }
                        if (p1x > sb.ulcx + sb.w) {
                            s1x = sb.ulcx + sb.w;
                        } else {
                            s1x = p1x;
                        }
                        if (p0y < sb.ulcy) {
                            s0y = sb.ulcy;
                        } else {
                            s0y = p0y;
                        }
                        if (p1y > sb.ulcy + sb.h) {
                            s1y = sb.ulcy + sb.h;
                        } else {
                            s1y = p1y;
                        }
                        cw = sb.nomCBlkW;
                        ch = sb.nomCBlkH;
                        k0 = (int) Math.floor(((double) (sb.ulcy - 0)) / ((double) ch));
                        kstart = (int) Math.floor(((double) (s0y - 0)) / ((double) ch));
                        kend = (int) Math.floor(((double) ((s1y - 1) - 0)) / ((double) ch));
                        l0 = (int) Math.floor(((double) (sb.ulcx - acb0x)) / ((double) cw));
                        lstart = (int) Math.floor(((double) (s0x - acb0x)) / ((double) cw));
                        lend = (int) Math.floor(((double) ((s1x - 1) - acb0x)) / ((double) cw));
                        if (s1x - s0x <= 0 || s1y - s0y <= 0) {
                            this.ppinfo[c][r][nPrec].nblk[2] = 0;
                            this.ttIncl[c][r][nPrec][2] = new TagTreeDecoder(0, 0);
                            this.ttMaxBP[c][r][nPrec][2] = new TagTreeDecoder(0, 0);
                        } else {
                            this.ttIncl[c][r][nPrec][2] = new TagTreeDecoder((kend - kstart) + 1, (lend - lstart) + 1);
                            this.ttMaxBP[c][r][nPrec][2] = new TagTreeDecoder((kend - kstart) + 1, (lend - lstart) + 1);
                            this.ppinfo[c][r][nPrec].cblk[2] = (CBlkCoordInfo[][]) Array.newInstance(CBlkCoordInfo.class, new int[]{(kend - kstart) + 1, (lend - lstart) + 1});
                            this.ppinfo[c][r][nPrec].nblk[2] = ((kend - kstart) + 1) * ((lend - lstart) + 1);
                            for (k = kstart; k <= kend; k++) {
                                for (l = lstart; l <= lend; l++) {
                                    cBlkCoordInfo = new CBlkCoordInfo(k - k0, l - l0);
                                    if (l == l0) {
                                        cBlkCoordInfo.ulx = sb.ulx;
                                    } else {
                                        cBlkCoordInfo.ulx = (sb.ulx + (l * cw)) - (sb.ulcx - acb0x);
                                    }
                                    if (k == k0) {
                                        cBlkCoordInfo.uly = sb.uly;
                                    } else {
                                        cBlkCoordInfo.uly = (sb.uly + (k * ch)) - (sb.ulcy - 0);
                                    }
                                    tmp1 = acb0x + (l * cw);
                                    if (tmp1 <= sb.ulcx) {
                                        tmp1 = sb.ulcx;
                                    }
                                    tmp2 = acb0x + ((l + 1) * cw);
                                    if (tmp2 > sb.ulcx + sb.w) {
                                        tmp2 = sb.ulcx + sb.w;
                                    }
                                    cBlkCoordInfo.w = tmp2 - tmp1;
                                    tmp1 = 0 + (k * ch);
                                    if (tmp1 <= sb.ulcy) {
                                        tmp1 = sb.ulcy;
                                    }
                                    tmp2 = 0 + ((k + 1) * ch);
                                    if (tmp2 > sb.ulcy + sb.h) {
                                        tmp2 = sb.ulcy + sb.h;
                                    }
                                    cBlkCoordInfo.h = tmp2 - tmp1;
                                    this.ppinfo[c][r][nPrec].cblk[2][k - kstart][l - lstart] = cBlkCoordInfo;
                                }
                            }
                        }
                        p0x = 0 + (j * twoppx2);
                        p1x = p0x + twoppx2;
                        p0y = 0 + (i * twoppy2);
                        p1y = p0y + twoppy2;
                        sb = (SubbandSyn) root.getSubbandByIdx(r, 3);
                        if (p0x < sb.ulcx) {
                            s0x = sb.ulcx;
                        } else {
                            s0x = p0x;
                        }
                        if (p1x > sb.ulcx + sb.w) {
                            s1x = sb.ulcx + sb.w;
                        } else {
                            s1x = p1x;
                        }
                        if (p0y < sb.ulcy) {
                            s0y = sb.ulcy;
                        } else {
                            s0y = p0y;
                        }
                        if (p1y > sb.ulcy + sb.h) {
                            s1y = sb.ulcy + sb.h;
                        } else {
                            s1y = p1y;
                        }
                        cw = sb.nomCBlkW;
                        ch = sb.nomCBlkH;
                        k0 = (int) Math.floor(((double) (sb.ulcy - 0)) / ((double) ch));
                        kstart = (int) Math.floor(((double) (s0y - 0)) / ((double) ch));
                        kend = (int) Math.floor(((double) ((s1y - 1) - 0)) / ((double) ch));
                        l0 = (int) Math.floor(((double) (sb.ulcx - 0)) / ((double) cw));
                        lstart = (int) Math.floor(((double) (s0x - 0)) / ((double) cw));
                        lend = (int) Math.floor(((double) ((s1x - 1) - 0)) / ((double) cw));
                        if (s1x - s0x <= 0 || s1y - s0y <= 0) {
                            this.ppinfo[c][r][nPrec].nblk[3] = 0;
                            this.ttIncl[c][r][nPrec][3] = new TagTreeDecoder(0, 0);
                            this.ttMaxBP[c][r][nPrec][3] = new TagTreeDecoder(0, 0);
                        } else {
                            this.ttIncl[c][r][nPrec][3] = new TagTreeDecoder((kend - kstart) + 1, (lend - lstart) + 1);
                            this.ttMaxBP[c][r][nPrec][3] = new TagTreeDecoder((kend - kstart) + 1, (lend - lstart) + 1);
                            this.ppinfo[c][r][nPrec].cblk[3] = (CBlkCoordInfo[][]) Array.newInstance(CBlkCoordInfo.class, new int[]{(kend - kstart) + 1, (lend - lstart) + 1});
                            this.ppinfo[c][r][nPrec].nblk[3] = ((kend - kstart) + 1) * ((lend - lstart) + 1);
                            for (k = kstart; k <= kend; k++) {
                                for (l = lstart; l <= lend; l++) {
                                    cBlkCoordInfo = new CBlkCoordInfo(k - k0, l - l0);
                                    if (l == l0) {
                                        cBlkCoordInfo.ulx = sb.ulx;
                                    } else {
                                        cBlkCoordInfo.ulx = (sb.ulx + (l * cw)) - (sb.ulcx - 0);
                                    }
                                    if (k == k0) {
                                        cBlkCoordInfo.uly = sb.uly;
                                    } else {
                                        cBlkCoordInfo.uly = (sb.uly + (k * ch)) - (sb.ulcy - 0);
                                    }
                                    tmp1 = 0 + (l * cw);
                                    if (tmp1 <= sb.ulcx) {
                                        tmp1 = sb.ulcx;
                                    }
                                    tmp2 = 0 + ((l + 1) * cw);
                                    if (tmp2 > sb.ulcx + sb.w) {
                                        tmp2 = sb.ulcx + sb.w;
                                    }
                                    cBlkCoordInfo.w = tmp2 - tmp1;
                                    tmp1 = 0 + (k * ch);
                                    if (tmp1 <= sb.ulcy) {
                                        tmp1 = sb.ulcy;
                                    }
                                    tmp2 = 0 + ((k + 1) * ch);
                                    if (tmp2 > sb.ulcy + sb.h) {
                                        tmp2 = sb.ulcy + sb.h;
                                    }
                                    cBlkCoordInfo.h = tmp2 - tmp1;
                                    this.ppinfo[c][r][nPrec].cblk[3][k - kstart][l - lstart] = cBlkCoordInfo;
                                }
                            }
                        }
                    }
                    j++;
                    nPrec++;
                }
            }
        }
    }

    public int getNumPrecinct(int c, int r) {
        return this.numPrec[c][r].f36x * this.numPrec[c][r].f37y;
    }

    public boolean readPktHead(int l, int r, int c, int p, CBlkInfo[][][] cbI, int[] nb) throws IOException {
        int sumtotnewtp = 0;
        int startPktHead = this.ehs.getPos();
        if (startPktHead >= this.ehs.length()) {
            return true;
        }
        PktHeaderBitReader bin;
        int s;
        int tIdx = this.src.getTileIdx();
        SubbandSyn root = this.src.getSynSubbandTree(tIdx, c);
        if (this.pph) {
            bin = new PktHeaderBitReader(this.pphbais);
        } else {
            bin = this.bin;
        }
        int mins = r == 0 ? 0 : 1;
        int maxs = r == 0 ? 1 : 4;
        boolean precFound = false;
        for (s = mins; s < maxs; s++) {
            if (p < this.ppinfo[c][r].length) {
                precFound = true;
            }
        }
        if (!precFound) {
            return false;
        }
        PrecInfo prec = this.ppinfo[c][r][p];
        bin.sync();
        int tmp;
        if (bin.readBit() == 0) {
            this.cblks = new Vector[(maxs + 1)];
            for (s = mins; s < maxs; s++) {
                this.cblks[s] = new Vector();
            }
            this.pktIdx++;
            if (this.isTruncMode && this.maxCB == -1) {
                tmp = this.ehs.getPos() - startPktHead;
                if (tmp > nb[tIdx]) {
                    nb[tIdx] = 0;
                    return true;
                }
                nb[tIdx] = nb[tIdx] - tmp;
            }
            if (this.ephUsed) {
                readEPHMarker(bin);
            }
            return false;
        }
        if (this.cblks == null || this.cblks.length < maxs + 1) {
            this.cblks = new Vector[(maxs + 1)];
        }
        s = mins;
        while (s < maxs) {
            Coord cbc;
            CBlkInfo cBlkInfo;
            int[] iArr;
            if (this.cblks[s] == null) {
                this.cblks[s] = new Vector();
            } else {
                this.cblks[s].removeAllElements();
            }
            SubbandSyn sb = (SubbandSyn) root.getSubbandByIdx(r, s);
            if (prec.nblk[s] != 0) {
                TagTreeDecoder tdIncl = this.ttIncl[c][r][p][s];
                TagTreeDecoder tdBD = this.ttMaxBP[c][r][p][s];
                int mend = prec.cblk[s] == null ? 0 : prec.cblk[s].length;
                for (int m = 0; m < mend; m++) {
                    int nend;
                    if (prec.cblk[s][m] == null) {
                        nend = 0;
                    } else {
                        nend = prec.cblk[s][m].length;
                    }
                    int n = 0;
                    while (n < nend) {
                        int totnewtp;
                        int options;
                        int nSeg;
                        int tpidx;
                        int passtype;
                        int i;
                        int cbLen;
                        int j;
                        int ltp;
                        cbc = prec.cblk[s][m][n].idx;
                        int b = cbc.f36x + (cbc.f37y * sb.numCb.f36x);
                        CBlkInfo ccb = cbI[s][cbc.f37y][cbc.f36x];
                        if (ccb != null) {
                            try {
                                if (ccb.ctp != 0) {
                                    ccb.pktIdx[l] = this.pktIdx;
                                    if (bin.readBit() != 1) {
                                        cBlkInfo = ccb;
                                        n++;
                                    } else {
                                        totnewtp = 1;
                                        cBlkInfo = ccb;
                                        if (bin.readBit() == 1) {
                                            totnewtp++;
                                            if (bin.readBit() == 1) {
                                                totnewtp++;
                                                tmp = bin.readBits(2);
                                                totnewtp = tmp + 3;
                                                if (tmp == 3) {
                                                    tmp = bin.readBits(5);
                                                    totnewtp += tmp;
                                                    if (tmp == 31) {
                                                        totnewtp += bin.readBits(7);
                                                    }
                                                }
                                            }
                                        }
                                        cBlkInfo.addNTP(l, totnewtp);
                                        sumtotnewtp += totnewtp;
                                        this.cblks[s].addElement(prec.cblk[s][m][n]);
                                        options = ((Integer) this.decSpec.ecopts.getTileCompVal(tIdx, c)).intValue();
                                        if ((options & 4) != 0) {
                                            nSeg = totnewtp;
                                        } else if ((options & 1) != 0) {
                                            nSeg = 1;
                                        } else if (cBlkInfo.ctp > 10) {
                                            nSeg = 1;
                                        } else {
                                            nSeg = 1;
                                            for (tpidx = cBlkInfo.ctp - totnewtp; tpidx < cBlkInfo.ctp - 1; tpidx++) {
                                                if (tpidx >= 9) {
                                                    passtype = (tpidx + 2) % 3;
                                                    if (passtype != 1 || passtype == 2) {
                                                        nSeg++;
                                                    }
                                                }
                                            }
                                        }
                                        while (bin.readBit() != 0) {
                                            iArr = this.lblock[c][r][s][cbc.f37y];
                                            i = cbc.f36x;
                                            iArr[i] = iArr[i] + 1;
                                        }
                                        if (nSeg != 1) {
                                            cbLen = bin.readBits(this.lblock[c][r][s][cbc.f37y][cbc.f36x] + MathUtil.log2(totnewtp));
                                        } else {
                                            cBlkInfo.segLen[l] = new int[nSeg];
                                            cbLen = 0;
                                            if ((options & 4) == 0) {
                                                tpidx = cBlkInfo.ctp - totnewtp;
                                                j = 0;
                                                while (tpidx < cBlkInfo.ctp) {
                                                    tmp = bin.readBits(this.lblock[c][r][s][cbc.f37y][cbc.f36x]);
                                                    cBlkInfo.segLen[l][j] = tmp;
                                                    cbLen += tmp;
                                                    tpidx++;
                                                    j++;
                                                }
                                            } else {
                                                ltp = (cBlkInfo.ctp - totnewtp) - 1;
                                                tpidx = cBlkInfo.ctp - totnewtp;
                                                j = 0;
                                                while (tpidx < cBlkInfo.ctp - 1) {
                                                    if (tpidx >= 9 && (tpidx + 2) % 3 != 0) {
                                                        tmp = bin.readBits(MathUtil.log2(tpidx - ltp) + this.lblock[c][r][s][cbc.f37y][cbc.f36x]);
                                                        cBlkInfo.segLen[l][j] = tmp;
                                                        cbLen += tmp;
                                                        ltp = tpidx;
                                                        j++;
                                                    }
                                                    tpidx++;
                                                }
                                                tmp = bin.readBits(MathUtil.log2(tpidx - ltp) + this.lblock[c][r][s][cbc.f37y][cbc.f36x]);
                                                cbLen += tmp;
                                                cBlkInfo.segLen[l][j] = tmp;
                                            }
                                        }
                                        cBlkInfo.len[l] = cbLen;
                                        if (this.isTruncMode && this.maxCB == -1 && this.ehs.getPos() - startPktHead > nb[tIdx]) {
                                            nb[tIdx] = 0;
                                            if (l != 0) {
                                                cbI[s][cbc.f37y][cbc.f36x] = null;
                                            } else {
                                                iArr = cBlkInfo.off;
                                                cBlkInfo.len[l] = 0;
                                                iArr[l] = 0;
                                                cBlkInfo.ctp -= cBlkInfo.ntp[l];
                                                cBlkInfo.ntp[l] = 0;
                                                cBlkInfo.pktIdx[l] = -1;
                                            }
                                            return true;
                                        }
                                        n++;
                                    }
                                }
                            } catch (EOFException e) {
                                cBlkInfo = ccb;
                            }
                        }
                        if (ccb == null) {
                            CBlkInfo[] cBlkInfoArr = cbI[s][cbc.f37y];
                            int i2 = cbc.f36x;
                            cBlkInfo = new CBlkInfo(prec.cblk[s][m][n].ulx, prec.cblk[s][m][n].uly, prec.cblk[s][m][n].w, prec.cblk[s][m][n].h, this.nl);
                            cBlkInfoArr[i2] = cBlkInfo;
                        } else {
                            cBlkInfo = ccb;
                        }
                        cBlkInfo.pktIdx[l] = this.pktIdx;
                        if (tdIncl.update(m, n, l + 1, bin) > l) {
                            continue;
                            n++;
                        } else {
                            tmp = 1;
                            int tmp2 = 1;
                            while (tmp >= tmp2) {
                                try {
                                    tmp = tdBD.update(m, n, tmp2, bin);
                                    tmp2++;
                                } catch (EOFException e2) {
                                }
                            }
                            cBlkInfo.msbSkipped = tmp2 - 2;
                            totnewtp = 1;
                            cBlkInfo.addNTP(l, 0);
                            this.ncb++;
                            if (!(this.maxCB == -1 || this.ncbQuit || this.ncb != this.maxCB)) {
                                this.ncbQuit = true;
                                this.tQuit = tIdx;
                                this.cQuit = c;
                                this.sQuit = s;
                                this.rQuit = r;
                                this.xQuit = cbc.f36x;
                                this.yQuit = cbc.f37y;
                            }
                            if (bin.readBit() == 1) {
                                totnewtp++;
                                if (bin.readBit() == 1) {
                                    totnewtp++;
                                    tmp = bin.readBits(2);
                                    totnewtp = tmp + 3;
                                    if (tmp == 3) {
                                        tmp = bin.readBits(5);
                                        totnewtp += tmp;
                                        if (tmp == 31) {
                                            totnewtp += bin.readBits(7);
                                        }
                                    }
                                }
                            }
                            cBlkInfo.addNTP(l, totnewtp);
                            sumtotnewtp += totnewtp;
                            this.cblks[s].addElement(prec.cblk[s][m][n]);
                            options = ((Integer) this.decSpec.ecopts.getTileCompVal(tIdx, c)).intValue();
                            if ((options & 4) != 0) {
                                nSeg = totnewtp;
                            } else if ((options & 1) != 0) {
                                nSeg = 1;
                            } else if (cBlkInfo.ctp > 10) {
                                nSeg = 1;
                                for (tpidx = cBlkInfo.ctp - totnewtp; tpidx < cBlkInfo.ctp - 1; tpidx++) {
                                    if (tpidx >= 9) {
                                        passtype = (tpidx + 2) % 3;
                                        if (passtype != 1) {
                                        }
                                        nSeg++;
                                    }
                                }
                            } else {
                                nSeg = 1;
                            }
                            while (bin.readBit() != 0) {
                                iArr = this.lblock[c][r][s][cbc.f37y];
                                i = cbc.f36x;
                                iArr[i] = iArr[i] + 1;
                            }
                            if (nSeg != 1) {
                                cBlkInfo.segLen[l] = new int[nSeg];
                                cbLen = 0;
                                if ((options & 4) == 0) {
                                    ltp = (cBlkInfo.ctp - totnewtp) - 1;
                                    tpidx = cBlkInfo.ctp - totnewtp;
                                    j = 0;
                                    while (tpidx < cBlkInfo.ctp - 1) {
                                        tmp = bin.readBits(MathUtil.log2(tpidx - ltp) + this.lblock[c][r][s][cbc.f37y][cbc.f36x]);
                                        cBlkInfo.segLen[l][j] = tmp;
                                        cbLen += tmp;
                                        ltp = tpidx;
                                        j++;
                                        tpidx++;
                                    }
                                    tmp = bin.readBits(MathUtil.log2(tpidx - ltp) + this.lblock[c][r][s][cbc.f37y][cbc.f36x]);
                                    cbLen += tmp;
                                    cBlkInfo.segLen[l][j] = tmp;
                                } else {
                                    tpidx = cBlkInfo.ctp - totnewtp;
                                    j = 0;
                                    while (tpidx < cBlkInfo.ctp) {
                                        tmp = bin.readBits(this.lblock[c][r][s][cbc.f37y][cbc.f36x]);
                                        cBlkInfo.segLen[l][j] = tmp;
                                        cbLen += tmp;
                                        tpidx++;
                                        j++;
                                    }
                                }
                            } else {
                                cbLen = bin.readBits(this.lblock[c][r][s][cbc.f37y][cbc.f36x] + MathUtil.log2(totnewtp));
                            }
                            cBlkInfo.len[l] = cbLen;
                            nb[tIdx] = 0;
                            if (l != 0) {
                                iArr = cBlkInfo.off;
                                cBlkInfo.len[l] = 0;
                                iArr[l] = 0;
                                cBlkInfo.ctp -= cBlkInfo.ntp[l];
                                cBlkInfo.ntp[l] = 0;
                                cBlkInfo.pktIdx[l] = -1;
                            } else {
                                cbI[s][cbc.f37y][cbc.f36x] = null;
                            }
                            return true;
                        }
                    }
                }
                continue;
            }
            s++;
        }
        if (this.ephUsed) {
            readEPHMarker(bin);
        }
        this.pktIdx++;
        if (this.isTruncMode && this.maxCB == -1) {
            tmp = this.ehs.getPos() - startPktHead;
            if (tmp > nb[tIdx]) {
                nb[tIdx] = 0;
                return true;
            }
            nb[tIdx] = nb[tIdx] - tmp;
        }
        return false;
        if (l == 0) {
            cbI[s][cbc.f37y][cbc.f36x] = null;
        } else {
            iArr = cBlkInfo.off;
            cBlkInfo.len[l] = 0;
            iArr[l] = 0;
            cBlkInfo.ctp -= cBlkInfo.ntp[l];
            cBlkInfo.ntp[l] = 0;
            cBlkInfo.pktIdx[l] = -1;
        }
        return true;
    }

    public boolean readPktBody(int l, int r, int c, int p, CBlkInfo[][][] cbI, int[] nb) throws IOException {
        int s;
        int curOff = this.ehs.getPos();
        boolean stopRead = false;
        int tIdx = this.src.getTileIdx();
        boolean precFound = false;
        int mins = r == 0 ? 0 : 1;
        int maxs = r == 0 ? 1 : 4;
        for (s = mins; s < maxs; s++) {
            if (p < this.ppinfo[c][r].length) {
                precFound = true;
            }
        }
        if (!precFound) {
            return false;
        }
        s = mins;
        while (s < maxs) {
            int numCB = 0;
            while (numCB < this.cblks[s].size()) {
                Coord cbc = ((CBlkCoordInfo) this.cblks[s].elementAt(numCB)).idx;
                CBlkInfo ccb = cbI[s][cbc.f37y][cbc.f36x];
                ccb.off[l] = curOff;
                curOff += ccb.len[l];
                int[] iArr;
                try {
                    this.ehs.seek(curOff);
                    if (this.isTruncMode) {
                        if (stopRead || ccb.len[l] > nb[tIdx]) {
                            if (l == 0) {
                                cbI[s][cbc.f37y][cbc.f36x] = null;
                            } else {
                                iArr = ccb.off;
                                ccb.len[l] = 0;
                                iArr[l] = 0;
                                ccb.ctp -= ccb.ntp[l];
                                ccb.ntp[l] = 0;
                                ccb.pktIdx[l] = -1;
                            }
                            stopRead = true;
                        }
                        if (!stopRead) {
                            nb[tIdx] = nb[tIdx] - ccb.len[l];
                        }
                    }
                    if (this.ncbQuit && r == this.rQuit && s == this.sQuit && cbc.f36x == this.xQuit && cbc.f37y == this.yQuit && tIdx == this.tQuit && c == this.cQuit) {
                        cbI[s][cbc.f37y][cbc.f36x] = null;
                        stopRead = true;
                    }
                    numCB++;
                } catch (EOFException e) {
                    if (l == 0) {
                        cbI[s][cbc.f37y][cbc.f36x] = null;
                    } else {
                        iArr = ccb.off;
                        ccb.len[l] = 0;
                        iArr[l] = 0;
                        ccb.ctp -= ccb.ntp[l];
                        ccb.ntp[l] = 0;
                        ccb.pktIdx[l] = -1;
                    }
                    throw new EOFException();
                }
            }
            s++;
        }
        this.ehs.seek(curOff);
        if (stopRead) {
            return true;
        }
        return false;
    }

    public final int getPPX(int t, int c, int r) {
        return this.decSpec.pss.getPPX(t, c, r);
    }

    public final int getPPY(int t, int c, int rl) {
        return this.decSpec.pss.getPPY(t, c, rl);
    }

    public boolean readSOPMarker(int[] nBytes, int p, int c, int r) throws IOException {
        byte[] sopArray = new byte[6];
        int tIdx = this.src.getTileIdx();
        int mins = r == 0 ? 0 : 1;
        int maxs = r == 0 ? 1 : 4;
        boolean precFound = false;
        for (int s = mins; s < maxs; s++) {
            if (p < this.ppinfo[c][r].length) {
                precFound = true;
            }
        }
        if (!precFound) {
            return false;
        }
        if (!this.sopUsed) {
            return false;
        }
        int pos = this.ehs.getPos();
        if (((short) ((this.ehs.read() << 8) | this.ehs.read())) != Markers.SOP) {
            this.ehs.seek(pos);
            return false;
        }
        this.ehs.seek(pos);
        if (nBytes[tIdx] < 6) {
            return true;
        }
        nBytes[tIdx] = nBytes[tIdx] - 6;
        this.ehs.readFully(sopArray, 0, 6);
        if (((sopArray[0] << 8) | sopArray[1]) != -111) {
            throw new Error("Corrupted Bitstream: Could not parse SOP marker !");
        } else if ((((sopArray[2] & 255) << 8) | (sopArray[3] & 255)) != 4) {
            throw new Error("Corrupted Bitstream: Corrupted SOP marker !");
        } else {
            int val = ((sopArray[4] & 255) << 8) | (sopArray[5] & 255);
            if (!this.pph && val != this.pktIdx) {
                throw new Error("Corrupted Bitstream: SOP marker out of sequence !");
            } else if (!this.pph || val == this.pktIdx - 1) {
                return false;
            } else {
                throw new Error("Corrupted Bitstream: SOP marker out of sequence !");
            }
        }
    }

    public void readEPHMarker(PktHeaderBitReader bin) throws IOException {
        byte[] ephArray = new byte[2];
        if (bin.usebais) {
            bin.bais.read(ephArray, 0, 2);
        } else {
            bin.in.readFully(ephArray, 0, 2);
        }
        if (((ephArray[0] << 8) | ephArray[1]) != -110) {
            throw new Error("Corrupted Bitstream: Could not parse EPH marker ! ");
        }
    }

    public PrecInfo getPrecInfo(int c, int r, int p) {
        return this.ppinfo[c][r][p];
    }
}
