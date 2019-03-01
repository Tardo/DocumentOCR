package jj2000.j2k.fileformat.reader;

import java.io.EOFException;
import java.io.IOException;
import java.util.Vector;
import jj2000.j2k.codestream.Markers;
import jj2000.j2k.fileformat.FileFormatBoxes;
import jj2000.j2k.io.RandomAccessIO;
import jj2000.j2k.util.FacilityManager;

public class FileFormatReader implements FileFormatBoxes {
    public boolean JP2FFUsed;
    private Vector codeStreamLength;
    private Vector codeStreamPos;
    private RandomAccessIO in;

    public FileFormatReader(RandomAccessIO in) {
        this.in = in;
    }

    public void readFileFormat() throws IOException, EOFException {
        long longLength = 0;
        boolean jp2HeaderBoxFound = false;
        boolean lastBoxFound = false;
        try {
            if (this.in.readInt() == 12 && this.in.readInt() == FileFormatBoxes.JP2_SIGNATURE_BOX && this.in.readInt() == 218793738) {
                this.JP2FFUsed = true;
                if (readFileTypeBox()) {
                    while (!lastBoxFound) {
                        int pos = this.in.getPos();
                        int length = this.in.readInt();
                        if (pos + length == this.in.length()) {
                            lastBoxFound = true;
                        }
                        int box = this.in.readInt();
                        if (length == 0) {
                            lastBoxFound = true;
                            length = this.in.length() - this.in.getPos();
                        } else if (length == 1) {
                            longLength = this.in.readLong();
                            throw new IOException("File too long.");
                        } else {
                            longLength = 0;
                        }
                        switch (box) {
                            case FileFormatBoxes.INTELLECTUAL_PROPERTY_BOX /*1685074537*/:
                                readIntPropertyBox(length);
                                break;
                            case FileFormatBoxes.CONTIGUOUS_CODESTREAM_BOX /*1785737827*/:
                                if (jp2HeaderBoxFound) {
                                    readContiguousCodeStreamBox((long) pos, length, longLength);
                                    break;
                                }
                                throw new Error("Invalid JP2 file: JP2Header box not found before Contiguous codestream box ");
                            case FileFormatBoxes.JP2_HEADER_BOX /*1785737832*/:
                                if (!jp2HeaderBoxFound) {
                                    readJP2HeaderBox((long) pos, length, longLength);
                                    jp2HeaderBoxFound = true;
                                    break;
                                }
                                throw new Error("Invalid JP2 file: Multiple JP2Header boxes found");
                            case FileFormatBoxes.UUID_INFO_BOX /*1969843814*/:
                                readUUIDInfoBox(length);
                                break;
                            case FileFormatBoxes.UUID_BOX /*1970628964*/:
                                readUUIDBox(length);
                                break;
                            case FileFormatBoxes.XML_BOX /*2020437024*/:
                                readXMLBox(length);
                                break;
                            default:
                                FacilityManager.getMsgLogger().printmsg(2, "Unknown box-type: 0x" + Integer.toHexString(box));
                                break;
                        }
                        if (!lastBoxFound) {
                            this.in.seek(pos + length);
                        }
                    }
                    if (this.codeStreamPos.size() == 0) {
                        throw new Error("Invalid JP2 file: Contiguous codestream box missing");
                    }
                    return;
                }
                throw new Error("Invalid JP2 file: File Type box missing");
            }
            this.in.seek(0);
            if (this.in.readShort() != Markers.SOC) {
                throw new Error("File is neither valid JP2 file nor valid JPEG 2000 codestream");
            }
            this.JP2FFUsed = false;
            this.in.seek(0);
        } catch (EOFException e) {
            throw new Error("EOF reached before finding Contiguous Codestream Box");
        }
    }

    public boolean readFileTypeBox() throws IOException, EOFException {
        boolean foundComp = false;
        int pos = this.in.getPos();
        int length = this.in.readInt();
        if (length == 0) {
            throw new Error("Zero-length of Profile Box");
        } else if (this.in.readInt() != FileFormatBoxes.FILE_TYPE_BOX) {
            return false;
        } else {
            if (length == 1) {
                long longLength = this.in.readLong();
                throw new IOException("File too long.");
            }
            this.in.readInt();
            this.in.readInt();
            for (int i = (length - 16) / 4; i > 0; i--) {
                if (this.in.readInt() == FileFormatBoxes.FT_BR) {
                    foundComp = true;
                }
            }
            if (foundComp) {
                return true;
            }
            return false;
        }
    }

    public boolean readJP2HeaderBox(long pos, int length, long longLength) throws IOException, EOFException {
        if (length != 0) {
            return true;
        }
        throw new Error("Zero-length of JP2Header Box");
    }

    public boolean readContiguousCodeStreamBox(long pos, int length, long longLength) throws IOException, EOFException {
        int ccpos = this.in.getPos();
        if (this.codeStreamPos == null) {
            this.codeStreamPos = new Vector();
        }
        this.codeStreamPos.addElement(new Integer(ccpos));
        if (this.codeStreamLength == null) {
            this.codeStreamLength = new Vector();
        }
        this.codeStreamLength.addElement(new Integer(length));
        return true;
    }

    public void readIntPropertyBox(int length) {
    }

    public void readXMLBox(int length) {
    }

    public void readUUIDBox(int length) {
    }

    public void readUUIDInfoBox(int length) {
    }

    public long[] getCodeStreamPos() {
        int size = this.codeStreamPos.size();
        long[] pos = new long[size];
        for (int i = 0; i < size; i++) {
            pos[i] = ((Integer) this.codeStreamPos.elementAt(i)).longValue();
        }
        return pos;
    }

    public int getFirstCodeStreamPos() {
        return ((Integer) this.codeStreamPos.elementAt(0)).intValue();
    }

    public int getFirstCodeStreamLength() {
        return ((Integer) this.codeStreamLength.elementAt(0)).intValue();
    }
}
