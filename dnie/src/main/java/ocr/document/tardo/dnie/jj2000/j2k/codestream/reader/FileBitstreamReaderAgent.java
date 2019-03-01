package jj2000.j2k.codestream.reader;

import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Vector;
import jj2000.j2k.JJ2KExceptionHandler;
import jj2000.j2k.NoNextElementException;
import jj2000.j2k.NotImplementedError;
import jj2000.j2k.codestream.CorruptedCodestreamException;
import jj2000.j2k.codestream.HeaderInfo;
import jj2000.j2k.codestream.HeaderInfo.SOT;
import jj2000.j2k.codestream.Markers;
import jj2000.j2k.codestream.PrecInfo;
import jj2000.j2k.codestream.ProgressionType;
import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.entropy.StdEntropyCoderOptions;
import jj2000.j2k.entropy.decoder.DecLyrdCBlk;
import jj2000.j2k.image.Coord;
import jj2000.j2k.io.RandomAccessIO;
import jj2000.j2k.quantization.dequantizer.StdDequantizerParams;
import jj2000.j2k.util.ArrayUtil;
import jj2000.j2k.util.FacilityManager;
import jj2000.j2k.util.MathUtil;
import jj2000.j2k.util.ParameterList;
import jj2000.j2k.wavelet.synthesis.SubbandSyn;

public class FileBitstreamReaderAgent extends BitstreamReaderAgent implements Markers, ProgressionType, StdEntropyCoderOptions {
    private int[] baknBytes;
    private CBlkInfo[][][][][] cbI;
    private int curTilePart;
    private int[][] firstPackOff;
    private int firstTilePartHeadLen;
    private int headLen = 0;
    private HeaderInfo hi;
    private RandomAccessIO in;
    private boolean isEOCFound = false;
    private boolean isPsotEqualsZero = true;
    private boolean isTruncMode;
    private int lQuit;
    private int mainHeadLen;
    private int[] nBytes;
    public PktDecoder pktDec;
    private Vector pktHL;
    private ParameterList pl;
    private boolean printInfo = false;
    private int remainingTileParts;
    private int[][] tilePartHeadLen;
    private int[][] tilePartLen;
    private int[][] tilePartNum;
    private int[] tileParts;
    private int[] tilePartsRead;
    private double totAllTileLen;
    private int[] totTileHeadLen;
    private int[] totTileLen;
    private int totTilePartsRead = 0;
    private boolean usePOCQuit = false;

    public int getNumTileParts(int t) {
        if (this.firstPackOff != null && this.firstPackOff[t] != null) {
            return this.firstPackOff[t].length;
        }
        throw new Error("Tile " + t + " not found in input codestream.");
    }

    public CBlkInfo[][][][][] getCBlkInfo() {
        return this.cbI;
    }

    public FileBitstreamReaderAgent(HeaderDecoder hd, RandomAccessIO ehs, DecoderSpecs decSpec, ParameterList pl, boolean cdstrInfo, HeaderInfo hi) throws IOException {
        int mdl;
        super(hd, decSpec);
        this.pl = pl;
        this.printInfo = cdstrInfo;
        this.hi = hi;
        String strInfo = "Codestream elements information in bytes (offset, total length, header length):\n\n";
        this.usePOCQuit = pl.getBooleanParameter("poc_quit");
        boolean parsing = pl.getBooleanParameter("parsing");
        try {
            this.trate = pl.getFloatParameter("rate");
            if (this.trate == -1.0f) {
                this.trate = Float.MAX_VALUE;
            }
            try {
                boolean rateInBytes;
                this.tnbytes = pl.getIntParameter("nbytes");
                if (((float) this.tnbytes) != pl.getDefaultParameterList().getFloatParameter("nbytes")) {
                    rateInBytes = true;
                } else {
                    rateInBytes = false;
                }
                if (rateInBytes) {
                    this.trate = ((((float) this.tnbytes) * 8.0f) / ((float) hd.getMaxCompImgWidth())) / ((float) hd.getMaxCompImgHeight());
                } else {
                    this.tnbytes = ((int) ((this.trate * ((float) hd.getMaxCompImgWidth())) * ((float) hd.getMaxCompImgHeight()))) / 8;
                }
                this.isTruncMode = !pl.getBooleanParameter("parsing");
                try {
                    int ncbQuit = pl.getIntParameter("ncb_quit");
                    if (ncbQuit == -1 || this.isTruncMode) {
                        try {
                            this.lQuit = pl.getIntParameter("l_quit");
                            this.in = ehs;
                            this.pktDec = new PktDecoder(decSpec, hd, ehs, this, this.isTruncMode, ncbQuit);
                            this.tileParts = new int[this.nt];
                            this.totTileLen = new int[this.nt];
                            this.tilePartLen = new int[this.nt][];
                            this.tilePartNum = new int[this.nt][];
                            this.firstPackOff = new int[this.nt][];
                            this.tilePartsRead = new int[this.nt];
                            this.totTileHeadLen = new int[this.nt];
                            this.tilePartHeadLen = new int[this.nt][];
                            this.nBytes = new int[this.nt];
                            this.baknBytes = new int[this.nt];
                            hd.nTileParts = new int[this.nt];
                            this.isTruncMode = this.isTruncMode;
                            int i = 0;
                            int tp = 0;
                            int tptot = 0;
                            int cdstreamStart = hd.mainHeadOff;
                            this.mainHeadLen = this.in.getPos() - cdstreamStart;
                            this.headLen = this.mainHeadLen;
                            if (ncbQuit == -1) {
                                this.anbytes = this.mainHeadLen;
                            } else {
                                this.anbytes = 0;
                            }
                            strInfo = strInfo + "Main header length    : " + cdstreamStart + ", " + this.mainHeadLen + ", " + this.mainHeadLen + "\n";
                            if (this.anbytes > this.tnbytes) {
                                throw new Error("Requested bitrate is too small.");
                            }
                            int tIdx;
                            boolean rateReached = false;
                            this.totAllTileLen = 0.0d;
                            this.remainingTileParts = this.nt;
                            int maxTP = this.nt;
                            do {
                                if (this.remainingTileParts == 0) {
                                    break;
                                }
                                int tilePartStart = this.in.getPos();
                                i = readTilePartHeader();
                                if (this.isEOCFound) {
                                    break;
                                }
                                try {
                                    tp = this.tilePartsRead[i];
                                    if (this.isPsotEqualsZero) {
                                        this.tilePartLen[i][tp] = (this.in.length() - 2) - tilePartStart;
                                    }
                                    int pos = this.in.getPos();
                                    if (this.isTruncMode && ncbQuit == -1 && pos - cdstreamStart > this.tnbytes) {
                                        this.firstPackOff[i][tp] = this.in.length();
                                        rateReached = true;
                                        break;
                                    }
                                    this.firstPackOff[i][tp] = pos;
                                    this.tilePartHeadLen[i][tp] = pos - tilePartStart;
                                    strInfo = strInfo + "Tile-part " + tp + " of tile " + i + " : " + tilePartStart + ", " + this.tilePartLen[i][tp] + ", " + this.tilePartHeadLen[i][tp] + "\n";
                                    int[] iArr = this.totTileLen;
                                    iArr[i] = iArr[i] + this.tilePartLen[i][tp];
                                    iArr = this.totTileHeadLen;
                                    iArr[i] = iArr[i] + this.tilePartHeadLen[i][tp];
                                    this.totAllTileLen += (double) this.tilePartLen[i][tp];
                                    if (!this.isTruncMode) {
                                        if (this.anbytes + this.tilePartHeadLen[i][tp] > this.tnbytes) {
                                            break;
                                        }
                                        this.anbytes += this.tilePartHeadLen[i][tp];
                                        this.headLen += this.tilePartHeadLen[i][tp];
                                    } else if (this.anbytes + this.tilePartLen[i][tp] > this.tnbytes) {
                                        this.anbytes += this.tilePartHeadLen[i][tp];
                                        this.headLen += this.tilePartHeadLen[i][tp];
                                        rateReached = true;
                                        iArr = this.nBytes;
                                        iArr[i] = iArr[i] + (this.tnbytes - this.anbytes);
                                        break;
                                    } else {
                                        this.anbytes += this.tilePartHeadLen[i][tp];
                                        this.headLen += this.tilePartHeadLen[i][tp];
                                        iArr = this.nBytes;
                                        iArr[i] = iArr[i] + (this.tilePartLen[i][tp] - this.tilePartHeadLen[i][tp]);
                                    }
                                    if (tptot == 0) {
                                        this.firstTilePartHeadLen = this.tilePartHeadLen[i][tp];
                                    }
                                    iArr = this.tilePartsRead;
                                    iArr[i] = iArr[i] + 1;
                                    this.in.seek(this.tilePartLen[i][tp] + tilePartStart);
                                    this.remainingTileParts--;
                                    maxTP--;
                                    tptot++;
                                } catch (EOFException e) {
                                    this.firstPackOff[i][tp] = this.in.length();
                                    throw e;
                                } catch (EOFException e2) {
                                    if (this.printInfo) {
                                        FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                    }
                                    FacilityManager.getMsgLogger().printmsg(2, "Codestream truncated in tile " + i);
                                    int fileLen = this.in.length();
                                    if (fileLen < this.tnbytes) {
                                        this.tnbytes = fileLen;
                                        this.trate = ((((float) this.tnbytes) * 8.0f) / ((float) hd.getMaxCompImgWidth())) / ((float) hd.getMaxCompImgHeight());
                                    }
                                    if (!this.isTruncMode) {
                                        allocateRate();
                                    }
                                    if (pl.getParameter("res") == null) {
                                        this.targetRes = decSpec.dls.getMin();
                                    } else {
                                        try {
                                            this.targetRes = pl.getIntParameter("res");
                                            if (this.targetRes < 0) {
                                                throw new IllegalArgumentException("Specified negative resolution level index: " + this.targetRes);
                                            }
                                        } catch (NumberFormatException e3) {
                                            throw new IllegalArgumentException("Invalid resolution level index ('-res' option) " + pl.getParameter("res"));
                                        }
                                    }
                                    mdl = decSpec.dls.getMin();
                                    if (this.targetRes > mdl) {
                                        FacilityManager.getMsgLogger().printmsg(2, "Specified resolution level (" + this.targetRes + ") is larger" + " than the maximum value. Setting it to " + mdl + " (maximum value)");
                                        this.targetRes = mdl;
                                    }
                                    for (tIdx = 0; tIdx < this.nt; tIdx++) {
                                        this.baknBytes[tIdx] = this.nBytes[tIdx];
                                    }
                                    return;
                                }
                            } while (!this.isPsotEqualsZero);
                            if (this.remainingTileParts != 0) {
                                FacilityManager.getMsgLogger().printmsg(2, "Some tile-parts have not been found. The codestream may be corrupted.");
                            }
                            this.remainingTileParts = 0;
                            if (pl.getParameter("res") == null) {
                                this.targetRes = decSpec.dls.getMin();
                            } else {
                                try {
                                    this.targetRes = pl.getIntParameter("res");
                                    if (this.targetRes < 0) {
                                        throw new IllegalArgumentException("Specified negative resolution level index: " + this.targetRes);
                                    }
                                } catch (NumberFormatException e4) {
                                    throw new IllegalArgumentException("Invalid resolution level index ('-res' option) " + pl.getParameter("res"));
                                }
                            }
                            mdl = decSpec.dls.getMin();
                            if (this.targetRes > mdl) {
                                FacilityManager.getMsgLogger().printmsg(2, "Specified resolution level (" + this.targetRes + ") is larger" + " than the maximum possible. Setting it to " + mdl + " (maximum possible)");
                                this.targetRes = mdl;
                            }
                            if (this.printInfo) {
                                FacilityManager.getMsgLogger().printmsg(1, strInfo);
                            }
                            if (!(this.isEOCFound || this.isPsotEqualsZero || rateReached)) {
                                try {
                                    if (!(this.isPsotEqualsZero || this.in.readShort() == (short) -39)) {
                                        FacilityManager.getMsgLogger().printmsg(2, "EOC marker not found. Codestream is corrupted.");
                                    }
                                } catch (EOFException e5) {
                                    FacilityManager.getMsgLogger().printmsg(2, "EOC marker is missing");
                                }
                            }
                            if (!this.isTruncMode) {
                                allocateRate();
                            } else if (this.in.getPos() >= this.tnbytes) {
                                this.anbytes += 2;
                            }
                            for (tIdx = 0; tIdx < this.nt; tIdx++) {
                                this.baknBytes[tIdx] = this.nBytes[tIdx];
                                if (this.printInfo) {
                                    FacilityManager.getMsgLogger().println("" + hi.toStringTileHeader(tIdx, this.tilePartLen[tIdx].length), 2, 2);
                                }
                            }
                            return;
                        } catch (NumberFormatException e6) {
                            throw new Error("Invalid value in 'l_quit' option: " + pl.getParameter("l_quit"));
                        } catch (IllegalArgumentException e7) {
                            throw new Error("'l_quit' option is missing");
                        }
                    }
                    throw new Error("Cannot use -parsing and -ncb_quit condition at the same time.");
                } catch (NumberFormatException e8) {
                    throw new Error("Invalid value in 'ncb_quit' option: " + pl.getParameter("ncb_quit"));
                } catch (IllegalArgumentException e9) {
                    throw new Error("'ncb_quit' option is missing");
                }
            } catch (NumberFormatException e10) {
                throw new Error("Invalid value in 'nbytes' option: " + pl.getParameter("nbytes"));
            } catch (IllegalArgumentException e11) {
                throw new Error("'nbytes' option is missing");
            }
        } catch (NumberFormatException e12) {
            throw new Error("Invalid value in 'rate' option: " + pl.getParameter("rate"));
        } catch (IllegalArgumentException e13) {
            throw new Error("'rate' option is missing");
        }
    }

    private void allocateRate() {
        int stopOff = this.tnbytes;
        this.anbytes += 2;
        if (this.anbytes > stopOff) {
            throw new Error("Requested bitrate is too small for parsing");
        }
        int rem = stopOff - this.anbytes;
        int totnByte = rem;
        for (int t = this.nt - 1; t > 0; t--) {
            int i = (int) (((double) totnByte) * (((double) this.totTileLen[t]) / this.totAllTileLen));
            this.nBytes[t] = i;
            rem -= i;
        }
        this.nBytes[0] = rem;
    }

    private int readTilePartHeader() throws IOException {
        boolean z = false;
        SOT ms = this.hi.getNewSOT();
        short marker = this.in.readShort();
        if (marker == Markers.SOT) {
            this.isEOCFound = false;
            int lsot = this.in.readUnsignedShort();
            ms.lsot = lsot;
            if (lsot != 10) {
                throw new CorruptedCodestreamException("Wrong length for SOT marker segment: " + lsot);
            }
            int tile = this.in.readUnsignedShort();
            ms.isot = tile;
            if (tile > 65534) {
                throw new CorruptedCodestreamException("Tile index too high in tile-part.");
            }
            int psot = this.in.readInt();
            ms.psot = psot;
            if (psot == 0) {
                z = true;
            }
            this.isPsotEqualsZero = z;
            if (psot < 0) {
                throw new NotImplementedError("Tile length larger than maximum supported");
            }
            int tilePart = this.in.read();
            ms.tpsot = tilePart;
            if (tilePart != this.tilePartsRead[tile] || tilePart < 0 || tilePart > 254) {
                throw new CorruptedCodestreamException("Out of order tile-part");
            }
            int nrOfTileParts = this.in.read();
            ms.tnsot = nrOfTileParts;
            this.hi.sot.put("t" + tile + "_tp" + tilePart, ms);
            int[] tmpA;
            int i;
            if (nrOfTileParts == 0) {
                int nExtraTp;
                if (this.tileParts[tile] == 0 || this.tileParts[tile] == this.tilePartLen.length) {
                    nExtraTp = 2;
                    this.remainingTileParts++;
                } else {
                    nExtraTp = 1;
                }
                int[] iArr = this.tileParts;
                iArr[tile] = iArr[tile] + nExtraTp;
                nrOfTileParts = this.tileParts[tile];
                FacilityManager.getMsgLogger().printmsg(2, "Header of tile-part " + tilePart + " of tile " + tile + ", does not indicate the total" + " number of tile-parts. Assuming that there are " + nrOfTileParts + " tile-parts for this tile.");
                tmpA = this.tilePartLen[tile];
                this.tilePartLen[tile] = new int[nrOfTileParts];
                for (i = 0; i < nrOfTileParts - nExtraTp; i++) {
                    this.tilePartLen[tile][i] = tmpA[i];
                }
                tmpA = this.tilePartNum[tile];
                this.tilePartNum[tile] = new int[nrOfTileParts];
                for (i = 0; i < nrOfTileParts - nExtraTp; i++) {
                    this.tilePartNum[tile][i] = tmpA[i];
                }
                tmpA = this.firstPackOff[tile];
                this.firstPackOff[tile] = new int[nrOfTileParts];
                for (i = 0; i < nrOfTileParts - nExtraTp; i++) {
                    this.firstPackOff[tile][i] = tmpA[i];
                }
                tmpA = this.tilePartHeadLen[tile];
                this.tilePartHeadLen[tile] = new int[nrOfTileParts];
                for (i = 0; i < nrOfTileParts - nExtraTp; i++) {
                    this.tilePartHeadLen[tile][i] = tmpA[i];
                }
            } else if (this.tileParts[tile] == 0) {
                this.remainingTileParts += nrOfTileParts - 1;
                this.tileParts[tile] = nrOfTileParts;
                this.tilePartLen[tile] = new int[nrOfTileParts];
                this.tilePartNum[tile] = new int[nrOfTileParts];
                this.firstPackOff[tile] = new int[nrOfTileParts];
                this.tilePartHeadLen[tile] = new int[nrOfTileParts];
            } else if (this.tileParts[tile] > nrOfTileParts) {
                throw new CorruptedCodestreamException("Invalid number of tile-parts in tile " + tile + ": " + nrOfTileParts);
            } else {
                this.remainingTileParts += nrOfTileParts - this.tileParts[tile];
                if (this.tileParts[tile] != nrOfTileParts) {
                    tmpA = this.tilePartLen[tile];
                    this.tilePartLen[tile] = new int[nrOfTileParts];
                    for (i = 0; i < this.tileParts[tile] - 1; i++) {
                        this.tilePartLen[tile][i] = tmpA[i];
                    }
                    tmpA = this.tilePartNum[tile];
                    this.tilePartNum[tile] = new int[nrOfTileParts];
                    for (i = 0; i < this.tileParts[tile] - 1; i++) {
                        this.tilePartNum[tile][i] = tmpA[i];
                    }
                    tmpA = this.firstPackOff[tile];
                    this.firstPackOff[tile] = new int[nrOfTileParts];
                    for (i = 0; i < this.tileParts[tile] - 1; i++) {
                        this.firstPackOff[tile][i] = tmpA[i];
                    }
                    tmpA = this.tilePartHeadLen[tile];
                    this.tilePartHeadLen[tile] = new int[nrOfTileParts];
                    for (i = 0; i < this.tileParts[tile] - 1; i++) {
                        this.tilePartHeadLen[tile][i] = tmpA[i];
                    }
                }
            }
            this.hd.resetHeaderMarkers();
            this.hd.nTileParts[tile] = nrOfTileParts;
            int numFoundMarkSeg;
            do {
                this.hd.extractTilePartMarkSeg(this.in.readShort(), this.in, tile, tilePart);
                numFoundMarkSeg = this.hd.getNumFoundMarkSeg();
                HeaderDecoder headerDecoder = this.hd;
            } while ((numFoundMarkSeg & 8192) == 0);
            this.hd.readFoundTilePartMarkSeg(tile, tilePart);
            this.tilePartLen[tile][tilePart] = psot;
            this.tilePartNum[tile][tilePart] = this.totTilePartsRead;
            this.totTilePartsRead++;
            this.hd.setTileOfTileParts(tile);
            return tile;
        } else if (marker == (short) -39) {
            this.isEOCFound = true;
            return -1;
        } else {
            throw new CorruptedCodestreamException("SOT tag not found in tile-part start");
        }
    }

    private boolean readLyResCompPos(int[][] lys, int lye, int ress, int rese, int comps, int compe) throws IOException {
        int minlys = 10000;
        int c = comps;
        while (c < compe) {
            int r;
            if (c < this.mdl.length) {
                r = ress;
                while (r < rese) {
                    if (lys[c] != null && r < lys[c].length && lys[c][r] < minlys) {
                        minlys = lys[c][r];
                    }
                    r++;
                }
            }
            c++;
        }
        int t = getTileIdx();
        int lastByte = ((this.firstPackOff[t][this.curTilePart] + this.tilePartLen[t][this.curTilePart]) - 1) - this.tilePartHeadLen[t][this.curTilePart];
        int numLayers = ((Integer) this.decSpec.nls.getTileDef(t)).intValue();
        String strInfo = "Tile " + getTileIdx() + " (tile-part:" + this.curTilePart + "): offset, length, header length\n";
        boolean pph = false;
        if (((Boolean) this.decSpec.pphs.getTileDef(t)).booleanValue()) {
            pph = true;
        }
        int l = minlys;
        while (l < lye) {
            r = ress;
            while (r < rese) {
                c = comps;
                while (c < compe) {
                    if (c < this.mdl.length && r < lys[c].length && r <= this.mdl[c] && l >= lys[c][r] && l < numLayers) {
                        int nPrec = this.pktDec.getNumPrecinct(c, r);
                        for (int p = 0; p < nPrec; p++) {
                            int start = this.in.getPos();
                            if (pph) {
                                this.pktDec.readPktHead(l, r, c, p, this.cbI[c][r], this.nBytes);
                            }
                            if (start > lastByte && this.curTilePart < this.firstPackOff[t].length - 1) {
                                this.curTilePart++;
                                this.in.seek(this.firstPackOff[t][this.curTilePart]);
                                lastByte = ((this.in.getPos() + this.tilePartLen[t][this.curTilePart]) - 1) - this.tilePartHeadLen[t][this.curTilePart];
                            }
                            boolean status = this.pktDec.readSOPMarker(this.nBytes, p, c, r);
                            if (status) {
                                if (this.printInfo) {
                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                }
                                return true;
                            }
                            if (!pph) {
                                status = this.pktDec.readPktHead(l, r, c, p, this.cbI[c][r], this.nBytes);
                            }
                            if (status) {
                                if (this.printInfo) {
                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                }
                                return true;
                            }
                            int hlen = this.in.getPos() - start;
                            this.pktHL.addElement(new Integer(hlen));
                            status = this.pktDec.readPktBody(l, r, c, p, this.cbI[c][r], this.nBytes);
                            strInfo = strInfo + " Pkt l=" + l + ",r=" + r + ",c=" + c + ",p=" + p + ": " + start + ", " + (this.in.getPos() - start) + ", " + hlen + "\n";
                            if (status) {
                                if (this.printInfo) {
                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                }
                                return true;
                            }
                        }
                        continue;
                    }
                    c++;
                }
                r++;
            }
            l++;
        }
        if (this.printInfo) {
            FacilityManager.getMsgLogger().printmsg(1, strInfo);
        }
        return false;
    }

    private boolean readResLyCompPos(int[][] lys, int lye, int ress, int rese, int comps, int compe) throws IOException {
        int r;
        int t = getTileIdx();
        int lastByte = ((this.firstPackOff[t][this.curTilePart] + this.tilePartLen[t][this.curTilePart]) - 1) - this.tilePartHeadLen[t][this.curTilePart];
        int minlys = 10000;
        int c = comps;
        while (c < compe) {
            if (c < this.mdl.length) {
                r = ress;
                while (r < rese) {
                    if (r <= this.mdl[c] && lys[c] != null && r < lys[c].length && lys[c][r] < minlys) {
                        minlys = lys[c][r];
                    }
                    r++;
                }
            }
            c++;
        }
        String strInfo = "Tile " + getTileIdx() + " (tile-part:" + this.curTilePart + "): offset, length, header length\n";
        int numLayers = ((Integer) this.decSpec.nls.getTileDef(t)).intValue();
        boolean pph = false;
        if (((Boolean) this.decSpec.pphs.getTileDef(t)).booleanValue()) {
            pph = true;
        }
        r = ress;
        while (r < rese) {
            int l = minlys;
            while (l < lye) {
                c = comps;
                while (c < compe) {
                    if (c < this.mdl.length && r <= this.mdl[c] && r < lys[c].length && l >= lys[c][r] && l < numLayers) {
                        int nPrec = this.pktDec.getNumPrecinct(c, r);
                        for (int p = 0; p < nPrec; p++) {
                            int start = this.in.getPos();
                            if (pph) {
                                this.pktDec.readPktHead(l, r, c, p, this.cbI[c][r], this.nBytes);
                            }
                            if (start > lastByte && this.curTilePart < this.firstPackOff[t].length - 1) {
                                this.curTilePart++;
                                this.in.seek(this.firstPackOff[t][this.curTilePart]);
                                lastByte = ((this.in.getPos() + this.tilePartLen[t][this.curTilePart]) - 1) - this.tilePartHeadLen[t][this.curTilePart];
                            }
                            boolean status = this.pktDec.readSOPMarker(this.nBytes, p, c, r);
                            if (status) {
                                if (this.printInfo) {
                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                }
                                return true;
                            }
                            if (!pph) {
                                status = this.pktDec.readPktHead(l, r, c, p, this.cbI[c][r], this.nBytes);
                            }
                            if (status) {
                                if (this.printInfo) {
                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                }
                                return true;
                            }
                            int hlen = this.in.getPos() - start;
                            this.pktHL.addElement(new Integer(hlen));
                            status = this.pktDec.readPktBody(l, r, c, p, this.cbI[c][r], this.nBytes);
                            strInfo = strInfo + " Pkt l=" + l + ",r=" + r + ",c=" + c + ",p=" + p + ": " + start + ", " + (this.in.getPos() - start) + ", " + hlen + "\n";
                            if (status) {
                                if (this.printInfo) {
                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                }
                                return true;
                            }
                        }
                        continue;
                    }
                    c++;
                }
                l++;
            }
            r++;
        }
        if (this.printInfo) {
            FacilityManager.getMsgLogger().printmsg(1, strInfo);
        }
        return false;
    }

    private boolean readResPosCompLy(int[][] lys, int lye, int ress, int rese, int comps, int compe) throws IOException {
        int tx1;
        int ty1;
        Coord nTiles = getNumTiles(null);
        Coord tileI = getTile(null);
        int x0siz = this.hd.getImgULX();
        int y0siz = this.hd.getImgULY();
        int xsiz = x0siz + this.hd.getImgWidth();
        int ysiz = y0siz + this.hd.getImgHeight();
        int xt0siz = getTilePartULX();
        int yt0siz = getTilePartULY();
        int xtsiz = getNomTileWidth();
        int ytsiz = getNomTileHeight();
        int tx0 = tileI.f36x == 0 ? x0siz : xt0siz + (tileI.f36x * xtsiz);
        int ty0 = tileI.f37y == 0 ? y0siz : yt0siz + (tileI.f37y * ytsiz);
        if (tileI.f36x != nTiles.f36x - 1) {
            tx1 = xt0siz + ((tileI.f36x + 1) * xtsiz);
        } else {
            tx1 = xsiz;
        }
        if (tileI.f37y != nTiles.f37y - 1) {
            ty1 = yt0siz + ((tileI.f37y + 1) * ytsiz);
        } else {
            ty1 = ysiz;
        }
        int t = getTileIdx();
        int gcd_x = 0;
        int gcd_y = 0;
        int nPrec = 0;
        int[][] nextPrec = new int[compe][];
        int minlys = 100000;
        int minx = tx1;
        int miny = ty1;
        int maxx = tx0;
        int maxy = ty0;
        int c = comps;
        while (c < compe) {
            int r = ress;
            while (r < rese) {
                PrecInfo prec;
                if (c < this.mdl.length && r <= this.mdl[c]) {
                    nextPrec[c] = new int[(this.mdl[c] + 1)];
                    if (lys[c] != null && r < lys[c].length && lys[c][r] < minlys) {
                        minlys = lys[c][r];
                    }
                    for (int p = this.pktDec.getNumPrecinct(c, r) - 1; p >= 0; p--) {
                        prec = this.pktDec.getPrecInfo(c, r, p);
                        if (prec.rgulx != tx0) {
                            if (prec.rgulx < minx) {
                                minx = prec.rgulx;
                            }
                            if (prec.rgulx > maxx) {
                                maxx = prec.rgulx;
                            }
                        }
                        if (prec.rguly != ty0) {
                            if (prec.rguly < miny) {
                                miny = prec.rguly;
                            }
                            if (prec.rguly > maxy) {
                                maxy = prec.rguly;
                            }
                        }
                        if (nPrec == 0) {
                            gcd_x = prec.rgw;
                            gcd_y = prec.rgh;
                        } else {
                            gcd_x = MathUtil.gcd(gcd_x, prec.rgw);
                            gcd_y = MathUtil.gcd(gcd_y, prec.rgh);
                        }
                        nPrec++;
                    }
                }
                r++;
            }
            c++;
        }
        if (nPrec == 0) {
            throw new Error("Image cannot have no precinct");
        }
        int pyend = ((maxy - miny) / gcd_y) + 1;
        int pxend = ((maxx - minx) / gcd_x) + 1;
        int lastByte = ((this.firstPackOff[t][this.curTilePart] + this.tilePartLen[t][this.curTilePart]) - 1) - this.tilePartHeadLen[t][this.curTilePart];
        int numLayers = ((Integer) this.decSpec.nls.getTileDef(t)).intValue();
        String strInfo = "Tile " + getTileIdx() + " (tile-part:" + this.curTilePart + "): offset, length, header length\n";
        boolean pph = false;
        if (((Boolean) this.decSpec.pphs.getTileDef(t)).booleanValue()) {
            pph = true;
        }
        r = ress;
        while (r < rese) {
            int y = ty0;
            int x = tx0;
            for (int py = 0; py <= pyend; py++) {
                for (int px = 0; px <= pxend; px++) {
                    c = comps;
                    while (c < compe) {
                        if (c < this.mdl.length && r <= this.mdl[c] && nextPrec[c][r] < this.pktDec.getNumPrecinct(c, r)) {
                            prec = this.pktDec.getPrecInfo(c, r, nextPrec[c][r]);
                            if (prec.rgulx == x && prec.rguly == y) {
                                int l = minlys;
                                while (l < lye) {
                                    if (r < lys[c].length && l >= lys[c][r] && l < numLayers) {
                                        int start = this.in.getPos();
                                        if (pph) {
                                            this.pktDec.readPktHead(l, r, c, nextPrec[c][r], this.cbI[c][r], this.nBytes);
                                        }
                                        if (start > lastByte && this.curTilePart < this.firstPackOff[t].length - 1) {
                                            this.curTilePart++;
                                            this.in.seek(this.firstPackOff[t][this.curTilePart]);
                                            lastByte = ((this.in.getPos() + this.tilePartLen[t][this.curTilePart]) - 1) - this.tilePartHeadLen[t][this.curTilePart];
                                        }
                                        boolean status = this.pktDec.readSOPMarker(this.nBytes, nextPrec[c][r], c, r);
                                        if (status) {
                                            if (this.printInfo) {
                                                FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                            }
                                            return true;
                                        }
                                        if (!pph) {
                                            status = this.pktDec.readPktHead(l, r, c, nextPrec[c][r], this.cbI[c][r], this.nBytes);
                                        }
                                        if (status) {
                                            if (this.printInfo) {
                                                FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                            }
                                            return true;
                                        }
                                        int hlen = this.in.getPos() - start;
                                        this.pktHL.addElement(new Integer(hlen));
                                        status = this.pktDec.readPktBody(l, r, c, nextPrec[c][r], this.cbI[c][r], this.nBytes);
                                        strInfo = strInfo + " Pkt l=" + l + ",r=" + r + ",c=" + c + ",p=" + nextPrec[c][r] + ": " + start + ", " + (this.in.getPos() - start) + ", " + hlen + "\n";
                                        if (status) {
                                            if (this.printInfo) {
                                                FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                            }
                                            return true;
                                        }
                                    }
                                    l++;
                                }
                                int[] iArr = nextPrec[c];
                                iArr[r] = iArr[r] + 1;
                            }
                        }
                        c++;
                    }
                    if (px != pxend) {
                        x = minx + (px * gcd_x);
                    } else {
                        x = tx0;
                    }
                }
                if (py != pyend) {
                    y = miny + (py * gcd_y);
                } else {
                    y = ty0;
                }
            }
            r++;
        }
        if (this.printInfo) {
            FacilityManager.getMsgLogger().printmsg(1, strInfo);
        }
        return false;
    }

    private boolean readPosCompResLy(int[][] lys, int lye, int ress, int rese, int comps, int compe) throws IOException {
        int tx1;
        int ty1;
        PrecInfo prec;
        Coord nTiles = getNumTiles(null);
        Coord tileI = getTile(null);
        int x0siz = this.hd.getImgULX();
        int y0siz = this.hd.getImgULY();
        int xsiz = x0siz + this.hd.getImgWidth();
        int ysiz = y0siz + this.hd.getImgHeight();
        int xt0siz = getTilePartULX();
        int yt0siz = getTilePartULY();
        int xtsiz = getNomTileWidth();
        int ytsiz = getNomTileHeight();
        int tx0 = tileI.f36x == 0 ? x0siz : xt0siz + (tileI.f36x * xtsiz);
        int ty0 = tileI.f37y == 0 ? y0siz : yt0siz + (tileI.f37y * ytsiz);
        if (tileI.f36x != nTiles.f36x - 1) {
            tx1 = xt0siz + ((tileI.f36x + 1) * xtsiz);
        } else {
            tx1 = xsiz;
        }
        if (tileI.f37y != nTiles.f37y - 1) {
            ty1 = yt0siz + ((tileI.f37y + 1) * ytsiz);
        } else {
            ty1 = ysiz;
        }
        int t = getTileIdx();
        int gcd_x = 0;
        int gcd_y = 0;
        int nPrec = 0;
        int[][] nextPrec = new int[compe][];
        int minlys = 100000;
        int minx = tx1;
        int miny = ty1;
        int maxx = tx0;
        int maxy = ty0;
        int c = comps;
        while (c < compe) {
            int r = ress;
            while (r < rese) {
                if (c < this.mdl.length && r <= this.mdl[c]) {
                    nextPrec[c] = new int[(this.mdl[c] + 1)];
                    if (lys[c] != null && r < lys[c].length && lys[c][r] < minlys) {
                        minlys = lys[c][r];
                    }
                    for (int p = this.pktDec.getNumPrecinct(c, r) - 1; p >= 0; p--) {
                        prec = this.pktDec.getPrecInfo(c, r, p);
                        if (prec.rgulx != tx0) {
                            if (prec.rgulx < minx) {
                                minx = prec.rgulx;
                            }
                            if (prec.rgulx > maxx) {
                                maxx = prec.rgulx;
                            }
                        }
                        if (prec.rguly != ty0) {
                            if (prec.rguly < miny) {
                                miny = prec.rguly;
                            }
                            if (prec.rguly > maxy) {
                                maxy = prec.rguly;
                            }
                        }
                        if (nPrec == 0) {
                            gcd_x = prec.rgw;
                            gcd_y = prec.rgh;
                        } else {
                            gcd_x = MathUtil.gcd(gcd_x, prec.rgw);
                            gcd_y = MathUtil.gcd(gcd_y, prec.rgh);
                        }
                        nPrec++;
                    }
                }
                r++;
            }
            c++;
        }
        if (nPrec == 0) {
            throw new Error("Image cannot have no precinct");
        }
        int pyend = ((maxy - miny) / gcd_y) + 1;
        int pxend = ((maxx - minx) / gcd_x) + 1;
        int lastByte = ((this.firstPackOff[t][this.curTilePart] + this.tilePartLen[t][this.curTilePart]) - 1) - this.tilePartHeadLen[t][this.curTilePart];
        int numLayers = ((Integer) this.decSpec.nls.getTileDef(t)).intValue();
        String strInfo = "Tile " + getTileIdx() + " (tile-part:" + this.curTilePart + "): offset, length, header length\n";
        boolean pph = false;
        if (((Boolean) this.decSpec.pphs.getTileDef(t)).booleanValue()) {
            pph = true;
        }
        int y = ty0;
        int x = tx0;
        for (int py = 0; py <= pyend; py++) {
            for (int px = 0; px <= pxend; px++) {
                c = comps;
                while (c < compe) {
                    if (c < this.mdl.length) {
                        r = ress;
                        while (r < rese) {
                            if (r <= this.mdl[c] && nextPrec[c][r] < this.pktDec.getNumPrecinct(c, r)) {
                                prec = this.pktDec.getPrecInfo(c, r, nextPrec[c][r]);
                                if (prec.rgulx == x && prec.rguly == y) {
                                    int l = minlys;
                                    while (l < lye) {
                                        if (r < lys[c].length && l >= lys[c][r] && l < numLayers) {
                                            int start = this.in.getPos();
                                            if (pph) {
                                                this.pktDec.readPktHead(l, r, c, nextPrec[c][r], this.cbI[c][r], this.nBytes);
                                            }
                                            if (start > lastByte && this.curTilePart < this.firstPackOff[t].length - 1) {
                                                this.curTilePart++;
                                                this.in.seek(this.firstPackOff[t][this.curTilePart]);
                                                lastByte = ((this.in.getPos() + this.tilePartLen[t][this.curTilePart]) - 1) - this.tilePartHeadLen[t][this.curTilePart];
                                            }
                                            boolean status = this.pktDec.readSOPMarker(this.nBytes, nextPrec[c][r], c, r);
                                            if (status) {
                                                if (this.printInfo) {
                                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                                }
                                                return true;
                                            }
                                            if (!pph) {
                                                status = this.pktDec.readPktHead(l, r, c, nextPrec[c][r], this.cbI[c][r], this.nBytes);
                                            }
                                            if (status) {
                                                if (this.printInfo) {
                                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                                }
                                                return true;
                                            }
                                            int hlen = this.in.getPos() - start;
                                            this.pktHL.addElement(new Integer(hlen));
                                            status = this.pktDec.readPktBody(l, r, c, nextPrec[c][r], this.cbI[c][r], this.nBytes);
                                            strInfo = strInfo + " Pkt l=" + l + ",r=" + r + ",c=" + c + ",p=" + nextPrec[c][r] + ": " + start + ", " + (this.in.getPos() - start) + ", " + hlen + "\n";
                                            if (status) {
                                                if (this.printInfo) {
                                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                                }
                                                return true;
                                            }
                                        }
                                        l++;
                                    }
                                    int[] iArr = nextPrec[c];
                                    iArr[r] = iArr[r] + 1;
                                }
                            }
                            r++;
                        }
                        continue;
                    }
                    c++;
                }
                if (px != pxend) {
                    x = minx + (px * gcd_x);
                } else {
                    x = tx0;
                }
            }
            if (py != pyend) {
                y = miny + (py * gcd_y);
            } else {
                y = ty0;
            }
        }
        if (this.printInfo) {
            FacilityManager.getMsgLogger().printmsg(1, strInfo);
        }
        return false;
    }

    private boolean readCompPosResLy(int[][] lys, int lye, int ress, int rese, int comps, int compe) throws IOException {
        int tx1;
        int ty1;
        Coord nTiles = getNumTiles(null);
        Coord tileI = getTile(null);
        int x0siz = this.hd.getImgULX();
        int y0siz = this.hd.getImgULY();
        int xsiz = x0siz + this.hd.getImgWidth();
        int ysiz = y0siz + this.hd.getImgHeight();
        int xt0siz = getTilePartULX();
        int yt0siz = getTilePartULY();
        int xtsiz = getNomTileWidth();
        int ytsiz = getNomTileHeight();
        int tx0 = tileI.f36x == 0 ? x0siz : xt0siz + (tileI.f36x * xtsiz);
        int ty0 = tileI.f37y == 0 ? y0siz : yt0siz + (tileI.f37y * ytsiz);
        if (tileI.f36x != nTiles.f36x - 1) {
            tx1 = xt0siz + ((tileI.f36x + 1) * xtsiz);
        } else {
            tx1 = xsiz;
        }
        if (tileI.f37y != nTiles.f37y - 1) {
            ty1 = yt0siz + ((tileI.f37y + 1) * ytsiz);
        } else {
            ty1 = ysiz;
        }
        int t = getTileIdx();
        int gcd_x = 0;
        int gcd_y = 0;
        int nPrec = 0;
        int[][] nextPrec = new int[compe][];
        int minlys = 100000;
        int minx = tx1;
        int miny = ty1;
        int maxx = tx0;
        int maxy = ty0;
        int c = comps;
        while (c < compe) {
            int r = ress;
            while (r < rese) {
                PrecInfo prec;
                if (c < this.mdl.length && r <= this.mdl[c]) {
                    nextPrec[c] = new int[(this.mdl[c] + 1)];
                    if (lys[c] != null && r < lys[c].length && lys[c][r] < minlys) {
                        minlys = lys[c][r];
                    }
                    for (int p = this.pktDec.getNumPrecinct(c, r) - 1; p >= 0; p--) {
                        prec = this.pktDec.getPrecInfo(c, r, p);
                        if (prec.rgulx != tx0) {
                            if (prec.rgulx < minx) {
                                minx = prec.rgulx;
                            }
                            if (prec.rgulx > maxx) {
                                maxx = prec.rgulx;
                            }
                        }
                        if (prec.rguly != ty0) {
                            if (prec.rguly < miny) {
                                miny = prec.rguly;
                            }
                            if (prec.rguly > maxy) {
                                maxy = prec.rguly;
                            }
                        }
                        if (nPrec == 0) {
                            gcd_x = prec.rgw;
                            gcd_y = prec.rgh;
                        } else {
                            gcd_x = MathUtil.gcd(gcd_x, prec.rgw);
                            gcd_y = MathUtil.gcd(gcd_y, prec.rgh);
                        }
                        nPrec++;
                    }
                }
                r++;
            }
            c++;
        }
        if (nPrec == 0) {
            throw new Error("Image cannot have no precinct");
        }
        int pyend = ((maxy - miny) / gcd_y) + 1;
        int pxend = ((maxx - minx) / gcd_x) + 1;
        int lastByte = ((this.firstPackOff[t][this.curTilePart] + this.tilePartLen[t][this.curTilePart]) - 1) - this.tilePartHeadLen[t][this.curTilePart];
        int numLayers = ((Integer) this.decSpec.nls.getTileDef(t)).intValue();
        String strInfo = "Tile " + getTileIdx() + " (tile-part:" + this.curTilePart + "): offset, length, header length\n";
        boolean pph = false;
        if (((Boolean) this.decSpec.pphs.getTileDef(t)).booleanValue()) {
            pph = true;
        }
        c = comps;
        while (c < compe) {
            if (c < this.mdl.length) {
                int y = ty0;
                int x = tx0;
                for (int py = 0; py <= pyend; py++) {
                    for (int px = 0; px <= pxend; px++) {
                        r = ress;
                        while (r < rese) {
                            if (r <= this.mdl[c] && nextPrec[c][r] < this.pktDec.getNumPrecinct(c, r)) {
                                prec = this.pktDec.getPrecInfo(c, r, nextPrec[c][r]);
                                if (prec.rgulx == x && prec.rguly == y) {
                                    int l = minlys;
                                    while (l < lye) {
                                        if (r < lys[c].length && l >= lys[c][r]) {
                                            int start = this.in.getPos();
                                            if (pph) {
                                                this.pktDec.readPktHead(l, r, c, nextPrec[c][r], this.cbI[c][r], this.nBytes);
                                            }
                                            if (start > lastByte && this.curTilePart < this.firstPackOff[t].length - 1) {
                                                this.curTilePart++;
                                                this.in.seek(this.firstPackOff[t][this.curTilePart]);
                                                lastByte = ((this.in.getPos() + this.tilePartLen[t][this.curTilePart]) - 1) - this.tilePartHeadLen[t][this.curTilePart];
                                            }
                                            boolean status = this.pktDec.readSOPMarker(this.nBytes, nextPrec[c][r], c, r);
                                            if (status) {
                                                if (this.printInfo) {
                                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                                }
                                                return true;
                                            }
                                            if (!pph) {
                                                status = this.pktDec.readPktHead(l, r, c, nextPrec[c][r], this.cbI[c][r], this.nBytes);
                                            }
                                            if (status) {
                                                if (this.printInfo) {
                                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                                }
                                                return true;
                                            }
                                            int hlen = this.in.getPos() - start;
                                            this.pktHL.addElement(new Integer(hlen));
                                            status = this.pktDec.readPktBody(l, r, c, nextPrec[c][r], this.cbI[c][r], this.nBytes);
                                            strInfo = strInfo + " Pkt l=" + l + ",r=" + r + ",c=" + c + ",p=" + nextPrec[c][r] + ": " + start + ", " + (this.in.getPos() - start) + ", " + hlen + "\n";
                                            if (status) {
                                                if (this.printInfo) {
                                                    FacilityManager.getMsgLogger().printmsg(1, strInfo);
                                                }
                                                return true;
                                            }
                                        }
                                        l++;
                                    }
                                    int[] iArr = nextPrec[c];
                                    iArr[r] = iArr[r] + 1;
                                }
                            }
                            r++;
                        }
                        if (px != pxend) {
                            x = minx + (px * gcd_x);
                        } else {
                            x = tx0;
                        }
                    }
                    if (py != pyend) {
                        y = miny + (py * gcd_y);
                    } else {
                        y = ty0;
                    }
                }
                continue;
            }
            c++;
        }
        if (this.printInfo) {
            FacilityManager.getMsgLogger().printmsg(1, strInfo);
        }
        return false;
    }

    private void readTilePkts(int t) throws IOException {
        int nChg;
        this.pktHL = new Vector();
        int nl = ((Integer) this.decSpec.nls.getTileDef(t)).intValue();
        if (((Boolean) this.decSpec.pphs.getTileDef(t)).booleanValue()) {
            this.cbI = this.pktDec.restart(this.nc, this.mdl, nl, this.cbI, true, this.hd.getPackedPktHead(t));
        } else {
            this.cbI = this.pktDec.restart(this.nc, this.mdl, nl, this.cbI, false, null);
        }
        int[][] pocSpec = (int[][]) this.decSpec.pcs.getTileDef(t);
        if (pocSpec == null) {
            nChg = 1;
        } else {
            nChg = pocSpec.length;
        }
        int[][] change = (int[][]) Array.newInstance(Integer.TYPE, new int[]{nChg, 6});
        change[0][1] = 0;
        if (pocSpec == null) {
            change[0][0] = ((Integer) this.decSpec.pos.getTileDef(t)).intValue();
            change[0][1] = nl;
            change[0][2] = 0;
            change[0][3] = this.decSpec.dls.getMaxInTile(t) + 1;
            change[0][4] = 0;
            change[0][5] = this.nc;
        } else {
            for (int idx = 0; idx < nChg; idx++) {
                change[idx][0] = pocSpec[idx][5];
                change[idx][1] = pocSpec[idx][2];
                change[idx][2] = pocSpec[idx][0];
                change[idx][3] = pocSpec[idx][3];
                change[idx][4] = pocSpec[idx][1];
                change[idx][5] = pocSpec[idx][4];
            }
        }
        try {
            if ((!this.isTruncMode || this.firstPackOff != null) && this.firstPackOff[t] != null) {
                int c;
                int r;
                boolean stopCount;
                int[] pktHeadLen;
                int i;
                boolean reject;
                int l;
                int nc;
                int mres;
                int msub;
                int s;
                int mnby;
                int m;
                int mnbx;
                int n;
                CBlkInfo cb;
                int[] iArr;
                int[] iArr2;
                int i2;
                this.in.seek(this.firstPackOff[t][0]);
                this.curTilePart = 0;
                boolean z = false;
                int nb = this.nBytes[t];
                int[][] lys = new int[this.nc][];
                for (c = 0; c < this.nc; c++) {
                    lys[c] = new int[(((Integer) this.decSpec.dls.getTileCompVal(t, c)).intValue() + 1)];
                }
                int chg = 0;
                while (chg < nChg) {
                    int lye = change[chg][1];
                    int ress = change[chg][2];
                    int rese = change[chg][3];
                    int comps = change[chg][4];
                    int compe = change[chg][5];
                    switch (change[chg][0]) {
                        case 0:
                            try {
                                z = readLyResCompPos(lys, lye, ress, rese, comps, compe);
                                break;
                            } catch (EOFException e) {
                                throw e;
                            }
                        case 1:
                            z = readResLyCompPos(lys, lye, ress, rese, comps, compe);
                            break;
                        case 2:
                            z = readResPosCompLy(lys, lye, ress, rese, comps, compe);
                            break;
                        case 3:
                            z = readPosCompResLy(lys, lye, ress, rese, comps, compe);
                            break;
                        case 4:
                            z = readCompPosResLy(lys, lye, ress, rese, comps, compe);
                            break;
                        default:
                            throw new IllegalArgumentException("Not recognized progression type");
                    }
                    for (c = comps; c < compe; c++) {
                        if (c < lys.length) {
                            for (r = ress; r < rese; r++) {
                                if (r < lys[c].length) {
                                    lys[c][r] = lye;
                                }
                            }
                        }
                    }
                    if (!(z || this.usePOCQuit)) {
                        chg++;
                    }
                    if (this.isTruncMode) {
                        this.anbytes += nb - this.nBytes[t];
                        if (z) {
                            this.nBytes[t] = 0;
                        }
                    } else if (this.nBytes[t] >= this.totTileLen[t] - this.totTileHeadLen[t]) {
                        stopCount = false;
                        pktHeadLen = new int[this.pktHL.size()];
                        for (i = this.pktHL.size() - 1; i >= 0; i--) {
                            pktHeadLen[i] = ((Integer) this.pktHL.elementAt(i)).intValue();
                        }
                        reject = false;
                        for (l = 0; l < nl; l++) {
                            if (this.cbI == null) {
                                nc = this.cbI.length;
                                mres = 0;
                                c = 0;
                                while (c < nc) {
                                    if (this.cbI[c] != null && this.cbI[c].length > mres) {
                                        mres = this.cbI[c].length;
                                    }
                                    c++;
                                }
                                r = 0;
                                while (r < mres) {
                                    msub = 0;
                                    c = 0;
                                    while (c < nc) {
                                        if (!(this.cbI[c] == null || this.cbI[c][r] == null || this.cbI[c][r].length <= msub)) {
                                            msub = this.cbI[c][r].length;
                                        }
                                        c++;
                                    }
                                    s = 0;
                                    while (s < msub) {
                                        if ((r != 0 || s == 0) && (r == 0 || s != 0)) {
                                            mnby = 0;
                                            c = 0;
                                            while (c < nc) {
                                                if (!(this.cbI[c] == null || this.cbI[c][r] == null || this.cbI[c][r][s] == null || this.cbI[c][r][s].length <= mnby)) {
                                                    mnby = this.cbI[c][r][s].length;
                                                }
                                                c++;
                                            }
                                            m = 0;
                                            while (m < mnby) {
                                                mnbx = 0;
                                                c = 0;
                                                while (c < nc) {
                                                    if (!(this.cbI[c] == null || this.cbI[c][r] == null || this.cbI[c][r][s] == null || this.cbI[c][r][s][m] == null || this.cbI[c][r][s][m].length <= mnbx)) {
                                                        mnbx = this.cbI[c][r][s][m].length;
                                                    }
                                                    c++;
                                                }
                                                n = 0;
                                                while (n < mnbx) {
                                                    c = 0;
                                                    while (c < nc) {
                                                        if (!(this.cbI[c] == null || this.cbI[c][r] == null || this.cbI[c][r][s] == null || this.cbI[c][r][s][m] == null || this.cbI[c][r][s][m][n] == null)) {
                                                            cb = this.cbI[c][r][s][m][n];
                                                            if (!reject) {
                                                                if (this.nBytes[t] < pktHeadLen[cb.pktIdx[l]]) {
                                                                    stopCount = true;
                                                                    reject = true;
                                                                } else if (!stopCount) {
                                                                    iArr = this.nBytes;
                                                                    iArr[t] = iArr[t] - pktHeadLen[cb.pktIdx[l]];
                                                                    this.anbytes += pktHeadLen[cb.pktIdx[l]];
                                                                    pktHeadLen[cb.pktIdx[l]] = 0;
                                                                }
                                                            }
                                                            if (cb.len[l] == 0) {
                                                                if (cb.len[l] < this.nBytes[t] || reject) {
                                                                    iArr = cb.len;
                                                                    iArr2 = cb.off;
                                                                    cb.ntp[l] = 0;
                                                                    iArr2[l] = 0;
                                                                    iArr[l] = 0;
                                                                    reject = true;
                                                                } else {
                                                                    iArr = this.nBytes;
                                                                    iArr[t] = iArr[t] - cb.len[l];
                                                                    this.anbytes += cb.len[l];
                                                                }
                                                            }
                                                        }
                                                        c++;
                                                    }
                                                    n++;
                                                }
                                                m++;
                                            }
                                        }
                                        s++;
                                    }
                                    r++;
                                }
                            }
                        }
                    } else {
                        this.anbytes += this.totTileLen[t] - this.totTileHeadLen[t];
                        if (t < getNumTiles() - 1) {
                            iArr = this.nBytes;
                            i2 = t + 1;
                            iArr[i2] = iArr[i2] + (this.nBytes[t] - (this.totTileLen[t] - this.totTileHeadLen[t]));
                        }
                    }
                }
                if (this.isTruncMode) {
                    this.anbytes += nb - this.nBytes[t];
                    if (z) {
                        this.nBytes[t] = 0;
                    }
                } else if (this.nBytes[t] >= this.totTileLen[t] - this.totTileHeadLen[t]) {
                    this.anbytes += this.totTileLen[t] - this.totTileHeadLen[t];
                    if (t < getNumTiles() - 1) {
                        iArr = this.nBytes;
                        i2 = t + 1;
                        iArr[i2] = iArr[i2] + (this.nBytes[t] - (this.totTileLen[t] - this.totTileHeadLen[t]));
                    }
                } else {
                    stopCount = false;
                    pktHeadLen = new int[this.pktHL.size()];
                    for (i = this.pktHL.size() - 1; i >= 0; i--) {
                        pktHeadLen[i] = ((Integer) this.pktHL.elementAt(i)).intValue();
                    }
                    reject = false;
                    while (l < nl) {
                        if (this.cbI == null) {
                            nc = this.cbI.length;
                            mres = 0;
                            c = 0;
                            while (c < nc) {
                                mres = this.cbI[c].length;
                                c++;
                            }
                            r = 0;
                            while (r < mres) {
                                msub = 0;
                                c = 0;
                                while (c < nc) {
                                    msub = this.cbI[c][r].length;
                                    c++;
                                }
                                s = 0;
                                while (s < msub) {
                                    mnby = 0;
                                    c = 0;
                                    while (c < nc) {
                                        mnby = this.cbI[c][r][s].length;
                                        c++;
                                    }
                                    m = 0;
                                    while (m < mnby) {
                                        mnbx = 0;
                                        c = 0;
                                        while (c < nc) {
                                            mnbx = this.cbI[c][r][s][m].length;
                                            c++;
                                        }
                                        n = 0;
                                        while (n < mnbx) {
                                            c = 0;
                                            while (c < nc) {
                                                cb = this.cbI[c][r][s][m][n];
                                                if (reject) {
                                                    if (this.nBytes[t] < pktHeadLen[cb.pktIdx[l]]) {
                                                        stopCount = true;
                                                        reject = true;
                                                    } else if (stopCount) {
                                                        iArr = this.nBytes;
                                                        iArr[t] = iArr[t] - pktHeadLen[cb.pktIdx[l]];
                                                        this.anbytes += pktHeadLen[cb.pktIdx[l]];
                                                        pktHeadLen[cb.pktIdx[l]] = 0;
                                                    }
                                                }
                                                if (cb.len[l] == 0) {
                                                    if (cb.len[l] < this.nBytes[t]) {
                                                    }
                                                    iArr = cb.len;
                                                    iArr2 = cb.off;
                                                    cb.ntp[l] = 0;
                                                    iArr2[l] = 0;
                                                    iArr[l] = 0;
                                                    reject = true;
                                                }
                                                c++;
                                            }
                                            n++;
                                        }
                                        m++;
                                    }
                                    s++;
                                }
                                r++;
                            }
                        }
                    }
                }
            }
        } catch (EOFException e2) {
            FacilityManager.getMsgLogger().printmsg(2, "Codestream truncated in tile " + t);
        }
    }

    public void setTile(int x, int y) {
        if (x < 0 || y < 0 || x >= this.ntX || y >= this.ntY) {
            throw new IllegalArgumentException();
        }
        int t = (this.ntX * y) + x;
        if (t == 0) {
            this.anbytes = this.headLen;
            if (!this.isTruncMode) {
                this.anbytes += 2;
            }
            for (int tIdx = 0; tIdx < this.nt; tIdx++) {
                this.nBytes[tIdx] = this.baknBytes[tIdx];
            }
        }
        this.ctX = x;
        this.ctY = y;
        int ctox = x == 0 ? this.ax : this.px + (this.ntW * x);
        int ctoy = y == 0 ? this.ay : this.py + (this.ntH * y);
        for (int i = this.nc - 1; i >= 0; i--) {
            this.culx[i] = ((this.hd.getCompSubsX(i) + ctox) - 1) / this.hd.getCompSubsX(i);
            this.culy[i] = ((this.hd.getCompSubsY(i) + ctoy) - 1) / this.hd.getCompSubsY(i);
            this.offX[i] = (((this.px + (this.ntW * x)) + this.hd.getCompSubsX(i)) - 1) / this.hd.getCompSubsX(i);
            this.offY[i] = (((this.py + (this.ntH * y)) + this.hd.getCompSubsY(i)) - 1) / this.hd.getCompSubsY(i);
        }
        this.subbTrees = new SubbandSyn[this.nc];
        this.mdl = new int[this.nc];
        this.derived = new boolean[this.nc];
        this.params = new StdDequantizerParams[this.nc];
        this.gb = new int[this.nc];
        for (int c = 0; c < this.nc; c++) {
            this.derived[c] = this.decSpec.qts.isDerived(t, c);
            this.params[c] = (StdDequantizerParams) this.decSpec.qsss.getTileCompVal(t, c);
            this.gb[c] = ((Integer) this.decSpec.gbs.getTileCompVal(t, c)).intValue();
            this.mdl[c] = ((Integer) this.decSpec.dls.getTileCompVal(t, c)).intValue();
            this.subbTrees[c] = new SubbandSyn(getTileCompWidth(t, c, this.mdl[c]), getTileCompHeight(t, c, this.mdl[c]), getResULX(c, this.mdl[c]), getResULY(c, this.mdl[c]), this.mdl[c], this.decSpec.wfs.getHFilters(t, c), this.decSpec.wfs.getVFilters(t, c));
            initSubbandsFields(c, this.subbTrees[c]);
        }
        try {
            readTilePkts(t);
        } catch (IOException e) {
            e.printStackTrace();
            throw new Error("IO Error when reading tile " + x + " x " + y);
        }
    }

    public void nextTile() {
        if (this.ctX == this.ntX - 1 && this.ctY == this.ntY - 1) {
            throw new NoNextElementException();
        } else if (this.ctX < this.ntX - 1) {
            setTile(this.ctX + 1, this.ctY);
        } else {
            setTile(0, this.ctY + 1);
        }
    }

    public DecLyrdCBlk getCodeBlock(int c, int m, int n, SubbandSyn sb, int fl, int nl, DecLyrdCBlk ccb) {
        int t = getTileIdx();
        int r = sb.resLvl;
        int s = sb.sbandIdx;
        int numLayers = ((Integer) this.decSpec.nls.getTileDef(t)).intValue();
        int options = ((Integer) this.decSpec.ecopts.getTileCompVal(t, c)).intValue();
        if (nl < 0) {
            nl = (numLayers - fl) + 1;
        }
        if (this.lQuit != -1 && fl + nl > this.lQuit) {
            nl = this.lQuit - fl;
        }
        if (r > (this.targetRes + getSynSubbandTree(t, c).resLvl) - this.decSpec.dls.getMin()) {
            throw new Error("JJ2000 error: requesting a code-block disallowed by the '-res' option.");
        }
        try {
            CBlkInfo rcb = this.cbI[c][r][s][m][n];
            if (fl < 1 || fl > numLayers || (fl + nl) - 1 > numLayers) {
                throw new IllegalArgumentException();
            }
            if (ccb == null) {
                ccb = new DecLyrdCBlk();
            }
            ccb.m = m;
            ccb.n = n;
            ccb.nl = 0;
            ccb.dl = 0;
            ccb.nTrunc = 0;
            if (rcb == null) {
                ccb.skipMSBP = 0;
                ccb.prog = false;
                ccb.uly = 0;
                ccb.ulx = 0;
                ccb.f215h = 0;
                ccb.f216w = 0;
            } else {
                int nts;
                int tpidx;
                ccb.skipMSBP = rcb.msbSkipped;
                ccb.ulx = rcb.ulx;
                ccb.uly = rcb.uly;
                ccb.f216w = rcb.f27w;
                ccb.f215h = rcb.f26h;
                ccb.ftpIdx = 0;
                int l = 0;
                while (l < rcb.len.length && rcb.len[l] == 0) {
                    ccb.ftpIdx += rcb.ntp[l];
                    l++;
                }
                for (l = fl - 1; l < (fl + nl) - 1; l++) {
                    ccb.nl++;
                    ccb.dl += rcb.len[l];
                    ccb.nTrunc += rcb.ntp[l];
                }
                if ((options & 4) != 0) {
                    nts = ccb.nTrunc - ccb.ftpIdx;
                } else if ((options & 1) == 0) {
                    nts = 1;
                } else if (ccb.nTrunc <= 10) {
                    nts = 1;
                } else {
                    nts = 1;
                    for (tpidx = ccb.ftpIdx; tpidx < ccb.nTrunc; tpidx++) {
                        if (tpidx >= 9) {
                            int passtype = (tpidx + 2) % 3;
                            if (passtype == 1 || passtype == 2) {
                                nts++;
                            }
                        }
                    }
                }
                if (ccb.data == null || ccb.data.length < ccb.dl) {
                    ccb.data = new byte[ccb.dl];
                }
                if (nts > 1 && (ccb.tsLengths == null || ccb.tsLengths.length < nts)) {
                    ccb.tsLengths = new int[nts];
                } else if (nts > 1 && (options & 5) == 1) {
                    ArrayUtil.intArraySet(ccb.tsLengths, 0);
                }
                int dataIdx = -1;
                tpidx = ccb.ftpIdx;
                int ctp = ccb.ftpIdx;
                int tsidx = 0;
                l = fl - 1;
                while (l < (fl + nl) - 1) {
                    ctp += rcb.ntp[l];
                    if (rcb.len[l] != 0) {
                        try {
                            this.in.seek(rcb.off[l]);
                            this.in.readFully(ccb.data, dataIdx + 1, rcb.len[l]);
                            dataIdx += rcb.len[l];
                        } catch (IOException e) {
                            JJ2KExceptionHandler.handleException(e);
                        }
                        if (nts != 1) {
                            int tsidx2;
                            int j;
                            if ((options & 4) != 0) {
                                j = 0;
                                tsidx2 = tsidx;
                                while (tpidx < ctp) {
                                    if (rcb.segLen[l] != null) {
                                        tsidx = tsidx2 + 1;
                                        ccb.tsLengths[tsidx2] = rcb.segLen[l][j];
                                    } else {
                                        tsidx = tsidx2 + 1;
                                        ccb.tsLengths[tsidx2] = rcb.len[l];
                                    }
                                    j++;
                                    tpidx++;
                                    tsidx2 = tsidx;
                                }
                            } else {
                                int[] iArr;
                                int j2 = 0;
                                tsidx2 = tsidx;
                                while (tpidx < ctp) {
                                    if (tpidx < 9 || (tpidx + 2) % 3 == 0) {
                                        j = j2;
                                        tsidx = tsidx2;
                                    } else if (rcb.segLen[l] != null) {
                                        iArr = ccb.tsLengths;
                                        tsidx = tsidx2 + 1;
                                        j = j2 + 1;
                                        iArr[tsidx2] = iArr[tsidx2] + rcb.segLen[l][j2];
                                        iArr = rcb.len;
                                        iArr[l] = iArr[l] - rcb.segLen[l][j - 1];
                                    } else {
                                        iArr = ccb.tsLengths;
                                        tsidx = tsidx2 + 1;
                                        iArr[tsidx2] = iArr[tsidx2] + rcb.len[l];
                                        rcb.len[l] = 0;
                                        j = j2;
                                    }
                                    tpidx++;
                                    j2 = j;
                                    tsidx2 = tsidx;
                                }
                                if (rcb.segLen[l] != null && j2 < rcb.segLen[l].length) {
                                    iArr = ccb.tsLengths;
                                    iArr[tsidx2] = iArr[tsidx2] + rcb.segLen[l][j2];
                                    iArr = rcb.len;
                                    iArr[l] = iArr[l] - rcb.segLen[l][j2];
                                    tsidx = tsidx2;
                                } else if (tsidx2 < nts) {
                                    iArr = ccb.tsLengths;
                                    iArr[tsidx2] = iArr[tsidx2] + rcb.len[l];
                                    rcb.len[l] = 0;
                                }
                            }
                            tsidx = tsidx2;
                        }
                    }
                    l++;
                }
                if (nts == 1 && ccb.tsLengths != null) {
                    ccb.tsLengths[0] = ccb.dl;
                }
                int lastlayer = (fl + nl) - 1;
                if (lastlayer < numLayers - 1) {
                    for (l = lastlayer + 1; l < numLayers; l++) {
                        if (rcb.len[l] != 0) {
                            ccb.prog = true;
                        }
                    }
                }
            }
            return ccb;
        } catch (ArrayIndexOutOfBoundsException e2) {
            throw new IllegalArgumentException("Code-block (t:" + t + ", c:" + c + ", r:" + r + ", s:" + s + ", " + m + "x" + n + ") not found in codestream");
        } catch (NullPointerException e3) {
            throw new IllegalArgumentException("Code-block (t:" + t + ", c:" + c + ", r:" + r + ", s:" + s + ", " + m + "x" + n + ") not found in bit stream");
        }
    }
}
