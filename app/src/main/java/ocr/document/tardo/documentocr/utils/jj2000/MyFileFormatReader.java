package ocr.document.tardo.documentocr.utils.jj2000;

import java.io.EOFException;
import java.io.IOException;
import java.util.Vector;
import jj2000.j2k.fileformat.FileFormatBoxes;
import jj2000.j2k.io.RandomAccessIO;
import jj2000.j2k.util.FacilityManager;

public class MyFileFormatReader implements FileFormatBoxes {
    private RandomAccessIO in;
    private Vector codeStreamPos;
    private Vector codeStreamLength;
    public boolean JP2FFUsed;

    public MyFileFormatReader(RandomAccessIO in) {
        this.in = in;
    }

    public void readFileFormat() throws IOException, EOFException {
        boolean foundCodeStreamBoxes = false;
        long longLength = 0L;
        boolean jp2HeaderBoxFound = false;
        boolean lastBoxFound = false;

        try {
           /* if(this.in.readInt() != 12)
                throw new IOException("File is neither valid JP2 file nor valid JPEG 2000 codestream");
            else if(this.in.readInt() != 1783636000)
                throw new IOException("File is neither valid JP2 file nor valid JPEG 2000 codestream");
            else if(this.in.readInt() != 218793738)
            //if(this.in.readInt() != 12 || this.in.readInt() != 1783636000 || this.in.readInt() != 218793738)
            {
                this.in.seek(0);
                short marker = this.in.readShort();
                if(marker != -177) {
                    throw new Error("File is neither valid JP2 file nor valid JPEG 2000 codestream");
                }

                this.JP2FFUsed = false;
                this.in.seek(0);
                return;
            }

            this.JP2FFUsed = true;
            if(!this.readFileTypeBox()) {
                throw new Error("Invalid JP2 file: File Type box missing");
            }*/

            this.in.seek(0); // <--- pruebas. para intentar posicionar el buffer.

            while(!lastBoxFound) {
                int pos = this.in.getPos();
                int length = this.in.readInt();
                if(pos + length == this.in.length()) {
                    lastBoxFound = true;
                }

                int box = this.in.readInt();
                if(length == 0) {
                    lastBoxFound = true;
                    length = this.in.length() - this.in.getPos();
                } else {
                    if(length == 1) {
                        longLength = this.in.readLong();
                        throw new IOException("File too long.");
                    }

                    longLength = 0L;
                }

                switch(box) {
                case 1685074537:
                    this.readIntPropertyBox(length);
                    break;
                case 1785737827:
                    if(!jp2HeaderBoxFound) {
                        throw new Error("Invalid JP2 file: JP2Header box not found before Contiguous codestream box ");
                    }

                    this.readContiguousCodeStreamBox((long)pos, length, longLength);
                    break;
                case 1785737832:
                    if(jp2HeaderBoxFound) {
                        throw new Error("Invalid JP2 file: Multiple JP2Header boxes found");
                    }

                    this.readJP2HeaderBox((long)pos, length, longLength);
                    jp2HeaderBoxFound = true;
                    break;
                case 1969843814:
                    this.readUUIDInfoBox(length);
                    break;
                case 1970628964:
                    this.readUUIDBox(length);
                    break;
                case 2020437024:
                    this.readXMLBox(length);
                    break;
                default:
                    FacilityManager.getMsgLogger().printmsg(2, "Unknown box-type: 0x" + Integer.toHexString(box));
                }

                if(!lastBoxFound) {
                    this.in.seek(pos + length);
                }
            }
        } catch (EOFException var11) {
            throw new Error("EOF reached before finding Contiguous Codestream Box");
        }

        if(this.codeStreamPos.size() == 0) {
            throw new Error("Invalid JP2 file: Contiguous codestream box missing");
        }
    }

    public boolean readFileTypeBox() throws IOException, EOFException {
        long longLength = 0L;
        boolean foundComp = false;
        int pos = this.in.getPos();
        int length = this.in.readInt();
        if(length == 0) {
            throw new Error("Zero-length of Profile Box");
        } else if(this.in.readInt() != 1718909296) {
            return false;
        } else if(length == 1) {
            longLength = this.in.readLong();
            throw new IOException("File too long.");
        } else {
            this.in.readInt();
            this.in.readInt();
            int nComp = (length - 16) / 4;

            for(int i = nComp; i > 0; --i) {
                if(this.in.readInt() == 1785737760) {
                    foundComp = true;
                }
            }

            if(!foundComp) {
                return false;
            } else {
                return true;
            }
        }
    }

    public boolean readJP2HeaderBox(long pos, int length, long longLength) throws IOException, EOFException {
        if(length == 0) {
            throw new Error("Zero-length of JP2Header Box");
        } else {
            return true;
        }
    }

    public boolean readContiguousCodeStreamBox(long pos, int length, long longLength) throws IOException, EOFException {
        int ccpos = this.in.getPos();
        if(this.codeStreamPos == null) {
            this.codeStreamPos = new Vector();
        }

        this.codeStreamPos.addElement(new Integer(ccpos));
        if(this.codeStreamLength == null) {
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

        for(int i = 0; i < size; ++i) {
            pos[i] = ((Integer)((Integer)this.codeStreamPos.elementAt(i))).longValue();
        }

        return pos;
    }

    public int getFirstCodeStreamPos() {
        return ((Integer)((Integer)this.codeStreamPos.elementAt(0))).intValue();
    }

    public int getFirstCodeStreamLength() {
        return ((Integer)((Integer)this.codeStreamLength.elementAt(0))).intValue();
    }
}
