package jj2000.j2k.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Vector;
import jj2000.j2k.codestream.Markers;
import jj2000.j2k.io.BEBufferedRandomAccessFile;
import jj2000.j2k.io.BufferedRandomAccessFile;

public class CodestreamManipulator {
    private static int MAX_TPSOT = 16;
    private static int TP_HEAD_LEN = 14;
    private byte[] mainHeader;
    private int maxtp;
    private int nt;
    private String outname;
    private byte[][][] packetData;
    private byte[][][] packetHeaders;
    private Integer[] positions;
    private boolean ppmUsed;
    private int[] ppt = new int[this.nt];
    private boolean pptUsed;
    private int pptp;
    private byte[][][] sopMarkSeg;
    private boolean tempEph;
    private boolean tempSop;
    private byte[][] tileHeaders;
    private byte[][][] tileParts;

    public CodestreamManipulator(String outname, int nt, int pptp, boolean ppm, boolean ppt, boolean tempSop, boolean tempEph) {
        this.outname = outname;
        this.nt = nt;
        this.pptp = pptp;
        this.ppmUsed = ppm;
        this.pptUsed = ppt;
        this.tempSop = tempSop;
        this.tempEph = tempEph;
    }

    public int doCodestreamManipulation() throws IOException {
        this.ppt = new int[this.nt];
        this.tileParts = new byte[this.nt][][];
        this.tileHeaders = new byte[this.nt][];
        this.packetHeaders = new byte[this.nt][][];
        this.packetData = new byte[this.nt][][];
        this.sopMarkSeg = new byte[this.nt][][];
        if (!this.ppmUsed && !this.pptUsed && this.pptp == 0) {
            return 0;
        }
        BEBufferedRandomAccessFile fi = new BEBufferedRandomAccessFile(this.outname, "rw+");
        int addedHeaderBytes = 0 - fi.length();
        parseAndFind(fi);
        readAndBuffer(fi);
        fi.close();
        fi = new BEBufferedRandomAccessFile(this.outname, "rw");
        createTileParts();
        writeNewCodestream(fi);
        fi.flush();
        addedHeaderBytes += fi.length();
        fi.close();
        return addedHeaderBytes;
    }

    private void parseAndFind(BufferedRandomAccessFile fi) throws IOException {
        int scod;
        Vector markPos = new Vector();
        short marker = (short) fi.readUnsignedShort();
        marker = (short) fi.readUnsignedShort();
        while (marker != Markers.SOT) {
            int pos = fi.getPos();
            int length = fi.readUnsignedShort();
            if (marker == Markers.COD) {
                scod = fi.readUnsignedByte();
                if (this.tempSop) {
                    scod &= 253;
                }
                if (this.tempEph) {
                    scod &= 251;
                }
                fi.seek(pos + 2);
                fi.write(scod);
            }
            fi.seek(pos + length);
            marker = (short) fi.readUnsignedShort();
        }
        fi.seek(fi.getPos() - 2);
        for (int t = 0; t < this.nt; t++) {
            fi.readUnsignedShort();
            pos = fi.getPos();
            markPos.addElement(new Integer(fi.getPos()));
            fi.readInt();
            length = fi.readInt();
            fi.readUnsignedShort();
            int tileEnd = (pos + length) - 2;
            marker = (short) fi.readUnsignedShort();
            while (marker != Markers.SOD) {
                pos = fi.getPos();
                length = fi.readUnsignedShort();
                if (marker == Markers.COD) {
                    scod = fi.readUnsignedByte();
                    if (this.tempSop) {
                        scod &= 253;
                    }
                    if (this.tempEph) {
                        scod &= 251;
                    }
                    fi.seek(pos + 2);
                    fi.write(scod);
                }
                fi.seek(pos + length);
                marker = (short) fi.readUnsignedShort();
            }
            int sop = 0;
            int eph = 0;
            int i = fi.getPos();
            while (i < tileEnd) {
                int halfMarker = (short) fi.readUnsignedByte();
                if (halfMarker == 255) {
                    marker = (short) ((halfMarker << 8) + fi.readUnsignedByte());
                    i++;
                    if (marker == Markers.SOP) {
                        markPos.addElement(new Integer(fi.getPos()));
                        int[] iArr = this.ppt;
                        iArr[t] = iArr[t] + 1;
                        sop++;
                        fi.skipBytes(4);
                        i += 4;
                    }
                    if (marker == Markers.EPH) {
                        markPos.addElement(new Integer(fi.getPos()));
                        eph++;
                    }
                }
                i++;
            }
        }
        markPos.addElement(new Integer(fi.getPos() + 2));
        this.positions = new Integer[markPos.size()];
        markPos.copyInto(this.positions);
    }

    private void readAndBuffer(BufferedRandomAccessFile fi) throws IOException {
        fi.seek(0);
        int length = this.positions[0].intValue() - 2;
        this.mainHeader = new byte[length];
        fi.readFully(this.mainHeader, 0, length);
        int markIndex = 0;
        for (int t = 0; t < this.nt; t++) {
            int prem = this.ppt[t];
            this.packetHeaders[t] = new byte[prem][];
            this.packetData[t] = new byte[prem][];
            this.sopMarkSeg[t] = new byte[prem][];
            length = this.positions[markIndex + 1].intValue() - this.positions[markIndex].intValue();
            this.tileHeaders[t] = new byte[length];
            fi.readFully(this.tileHeaders[t], 0, length);
            markIndex++;
            for (int p = 0; p < prem; p++) {
                length = this.positions[markIndex + 1].intValue() - this.positions[markIndex].intValue();
                if (this.tempSop) {
                    length -= 6;
                    fi.skipBytes(6);
                } else {
                    length -= 6;
                    this.sopMarkSeg[t][p] = new byte[6];
                    fi.readFully(this.sopMarkSeg[t][p], 0, 6);
                }
                if (!this.tempEph) {
                    length += 2;
                }
                this.packetHeaders[t][p] = new byte[length];
                fi.readFully(this.packetHeaders[t][p], 0, length);
                markIndex++;
                length = (this.positions[markIndex + 1].intValue() - this.positions[markIndex].intValue()) - 2;
                if (this.tempEph) {
                    fi.skipBytes(2);
                }
                this.packetData[t][p] = new byte[length];
                fi.readFully(this.packetData[t][p], 0, length);
                markIndex++;
            }
        }
    }

    private void createTileParts() throws IOException {
        ByteArrayOutputStream temp = new ByteArrayOutputStream();
        this.tileParts = new byte[this.nt][][];
        this.maxtp = 0;
        for (int t = 0; t < this.nt; t++) {
            int i;
            if (this.pptp == 0) {
                this.pptp = this.ppt[t];
            }
            int prem = this.ppt[t];
            int numTileParts = (int) Math.ceil(((double) prem) / ((double) this.pptp));
            int numPackets = this.packetHeaders[t].length;
            if (numTileParts > this.maxtp) {
                i = numTileParts;
            } else {
                i = this.maxtp;
            }
            this.maxtp = i;
            this.tileParts[t] = new byte[numTileParts][];
            int tppStart = 0;
            int pIndex = 0;
            int p = 0;
            for (int tilePart = 0; tilePart < numTileParts; tilePart++) {
                int nomnp = this.pptp > prem ? prem : this.pptp;
                int np = nomnp;
                if (tilePart == 0) {
                    temp.write(this.tileHeaders[t], 0, this.tileHeaders[t].length - 2);
                } else {
                    temp.write(new byte[(TP_HEAD_LEN - 2)], 0, TP_HEAD_LEN - 2);
                }
                if (this.pptUsed) {
                    int i2;
                    int pptLength = 3;
                    p = pIndex;
                    int pptIndex = 0;
                    while (np > 0) {
                        int pptIndex2;
                        int phLength = this.packetHeaders[t][p].length;
                        if (pptLength + phLength > 65535) {
                            temp.write(16777215);
                            temp.write(-159);
                            temp.write(pptLength >>> 8);
                            temp.write(pptLength);
                            pptIndex2 = pptIndex + 1;
                            temp.write(pptIndex);
                            for (i2 = pIndex; i2 < p; i2++) {
                                temp.write(this.packetHeaders[t][i2], 0, this.packetHeaders[t][i2].length);
                            }
                            pptLength = 3;
                            pIndex = p;
                        } else {
                            pptIndex2 = pptIndex;
                        }
                        pptLength += phLength;
                        p++;
                        np--;
                        pptIndex = pptIndex2;
                    }
                    temp.write(16777215);
                    temp.write(-159);
                    temp.write(pptLength >>> 8);
                    temp.write(pptLength);
                    temp.write(pptIndex);
                    for (i2 = pIndex; i2 < p; i2++) {
                        temp.write(this.packetHeaders[t][i2], 0, this.packetHeaders[t][i2].length);
                    }
                }
                pIndex = p;
                np = nomnp;
                temp.write(16777215);
                temp.write(-109);
                p = tppStart;
                while (p < tppStart + np) {
                    if (!this.tempSop) {
                        temp.write(this.sopMarkSeg[t][p], 0, 6);
                    }
                    if (!(this.ppmUsed || this.pptUsed)) {
                        temp.write(this.packetHeaders[t][p], 0, this.packetHeaders[t][p].length);
                    }
                    temp.write(this.packetData[t][p], 0, this.packetData[t][p].length);
                    p++;
                }
                tppStart += np;
                byte[] tempByteArr = temp.toByteArray();
                this.tileParts[t][tilePart] = tempByteArr;
                int length = temp.size();
                if (tilePart == 0) {
                    tempByteArr[6] = (byte) (length >>> 24);
                    tempByteArr[7] = (byte) (length >>> 16);
                    tempByteArr[8] = (byte) (length >>> 8);
                    tempByteArr[9] = (byte) length;
                    tempByteArr[10] = (byte) 0;
                    tempByteArr[11] = (byte) numTileParts;
                } else {
                    tempByteArr[0] = (byte) -1;
                    tempByteArr[1] = (byte) -112;
                    tempByteArr[2] = (byte) 0;
                    tempByteArr[3] = (byte) 10;
                    tempByteArr[4] = (byte) (t >>> 8);
                    tempByteArr[5] = (byte) t;
                    tempByteArr[6] = (byte) (length >>> 24);
                    tempByteArr[7] = (byte) (length >>> 16);
                    tempByteArr[8] = (byte) (length >>> 8);
                    tempByteArr[9] = (byte) length;
                    tempByteArr[10] = (byte) tilePart;
                    tempByteArr[11] = (byte) numTileParts;
                }
                temp.reset();
                prem -= np;
            }
        }
        temp.close();
    }

    private void writeNewCodestream(BufferedRandomAccessFile fi) throws IOException {
        int t;
        int tp;
        byte[] temp;
        int numTiles = this.tileParts.length;
        int[][] packetHeaderLengths = (int[][]) Array.newInstance(Integer.TYPE, new int[]{numTiles, this.maxtp});
        fi.write(this.mainHeader, 0, this.mainHeader.length);
        if (this.ppmUsed) {
            int totNumPackets;
            int numPackets;
            int pStart;
            int pStop;
            int p;
            int length;
            ByteArrayOutputStream ppmMarkerSegment = new ByteArrayOutputStream();
            int[] prem = new int[numTiles];
            for (t = 0; t < numTiles; t++) {
                prem[t] = this.packetHeaders[t].length;
            }
            for (tp = 0; tp < this.maxtp; tp++) {
                for (t = 0; t < numTiles; t++) {
                    if (this.tileParts[t].length > tp) {
                        totNumPackets = this.packetHeaders[t].length;
                        if (tp == this.tileParts[t].length - 1) {
                            numPackets = prem[t];
                        } else {
                            numPackets = this.pptp;
                        }
                        pStart = totNumPackets - prem[t];
                        pStop = pStart + numPackets;
                        for (p = pStart; p < pStop; p++) {
                            int[] iArr = packetHeaderLengths[t];
                            iArr[tp] = iArr[tp] + this.packetHeaders[t][p].length;
                        }
                        prem[t] = prem[t] - numPackets;
                    }
                }
            }
            ppmMarkerSegment.write(16777215);
            ppmMarkerSegment.write(-160);
            ppmMarkerSegment.write(0);
            ppmMarkerSegment.write(0);
            ppmMarkerSegment.write(0);
            int ppmLength = 3;
            int ppmIndex = 0 + 1;
            for (t = 0; t < numTiles; t++) {
                prem[t] = this.packetHeaders[t].length;
            }
            tp = 0;
            while (tp < this.maxtp) {
                t = 0;
                int ppmIndex2 = ppmIndex;
                while (t < numTiles) {
                    if (this.tileParts[t].length > tp) {
                        totNumPackets = this.packetHeaders[t].length;
                        if (tp == this.tileParts[t].length - 1) {
                            numPackets = prem[t];
                        } else {
                            numPackets = this.pptp;
                        }
                        pStart = totNumPackets - prem[t];
                        pStop = pStart + numPackets;
                        if (ppmLength + 4 > 65535) {
                            temp = ppmMarkerSegment.toByteArray();
                            length = temp.length - 2;
                            temp[2] = (byte) (length >>> 8);
                            temp[3] = (byte) length;
                            fi.write(temp, 0, length + 2);
                            ppmMarkerSegment.reset();
                            ppmMarkerSegment.write(16777215);
                            ppmMarkerSegment.write(-160);
                            ppmMarkerSegment.write(0);
                            ppmMarkerSegment.write(0);
                            ppmIndex = ppmIndex2 + 1;
                            ppmMarkerSegment.write(ppmIndex2);
                            ppmLength = 3;
                        } else {
                            ppmIndex = ppmIndex2;
                        }
                        length = packetHeaderLengths[t][tp];
                        ppmMarkerSegment.write(length >>> 24);
                        ppmMarkerSegment.write(length >>> 16);
                        ppmMarkerSegment.write(length >>> 8);
                        ppmMarkerSegment.write(length);
                        ppmLength += 4;
                        p = pStart;
                        ppmIndex2 = ppmIndex;
                        while (p < pStop) {
                            if (ppmLength + this.packetHeaders[t][p].length > 65535) {
                                temp = ppmMarkerSegment.toByteArray();
                                length = temp.length - 2;
                                temp[2] = (byte) (length >>> 8);
                                temp[3] = (byte) length;
                                fi.write(temp, 0, length + 2);
                                ppmMarkerSegment.reset();
                                ppmMarkerSegment.write(16777215);
                                ppmMarkerSegment.write(-160);
                                ppmMarkerSegment.write(0);
                                ppmMarkerSegment.write(0);
                                ppmIndex = ppmIndex2 + 1;
                                ppmMarkerSegment.write(ppmIndex2);
                                ppmLength = 3;
                            } else {
                                ppmIndex = ppmIndex2;
                            }
                            ppmMarkerSegment.write(this.packetHeaders[t][p], 0, this.packetHeaders[t][p].length);
                            ppmLength += this.packetHeaders[t][p].length;
                            p++;
                            ppmIndex2 = ppmIndex;
                        }
                        prem[t] = prem[t] - numPackets;
                    }
                    t++;
                    ppmIndex2 = ppmIndex2;
                }
                tp++;
                ppmIndex = ppmIndex2;
            }
            temp = ppmMarkerSegment.toByteArray();
            length = temp.length - 2;
            temp[2] = (byte) (length >>> 8);
            temp[3] = (byte) length;
            fi.write(temp, 0, length + 2);
        }
        for (tp = 0; tp < this.maxtp; tp++) {
            for (t = 0; t < this.nt; t++) {
                if (this.tileParts[t].length > tp) {
                    temp = this.tileParts[t][tp];
                    fi.write(temp, 0, temp.length);
                }
            }
        }
        fi.writeShort(-39);
    }
}
