package colorspace;

import colorspace.boxes.ChannelDefinitionBox;
import colorspace.boxes.ColorSpecificationBox;
import colorspace.boxes.ComponentMappingBox;
import colorspace.boxes.ImageHeaderBox;
import colorspace.boxes.PaletteBox;
import icc.ICCProfile;
import java.io.IOException;
import jj2000.j2k.codestream.reader.HeaderDecoder;
import jj2000.j2k.fileformat.FileFormatBoxes;
import jj2000.j2k.io.RandomAccessIO;
import jj2000.j2k.util.ParameterList;

public class ColorSpace {
    static final int BLUE = 3;
    public static final MethodEnum ENUMERATED = new MethodEnum("enumerated");
    static final int GRAY = 0;
    static final int GREEN = 2;
    public static final CSEnum GreyScale = new CSEnum("GreyScale");
    public static final MethodEnum ICC_PROFILED = new MethodEnum("profiled");
    public static final CSEnum Illegal = new CSEnum("Illegal");
    static final int RED = 1;
    public static final CSEnum Unknown = new CSEnum("Unknown");
    public static final String eol = System.getProperty("line.separator");
    public static final CSEnum sRGB = new CSEnum("sRGB");
    public static final CSEnum sYCC = new CSEnum("sYCC");
    private ChannelDefinitionBox cdbox = null;
    private ComponentMappingBox cmbox = null;
    private ColorSpecificationBox csbox = null;
    public HeaderDecoder hd;
    private ImageHeaderBox ihbox = null;
    private RandomAccessIO in = null;
    private PaletteBox pbox = null;
    public ParameterList pl;

    public static class Enumeration {
        public final String value;

        public Enumeration(String value) {
            this.value = value;
        }

        public String toString() {
            return this.value;
        }
    }

    public static class CSEnum extends Enumeration {
        public CSEnum(String value) {
            super(value);
        }
    }

    public static class MethodEnum extends Enumeration {
        public MethodEnum(String value) {
            super(value);
        }
    }

    public byte[] getICCProfile() {
        return this.csbox.getICCProfile();
    }

    public static String indent(String ident, StringBuffer instr) {
        return indent(ident, instr.toString());
    }

    public static String indent(String ident, String instr) {
        StringBuffer tgt = new StringBuffer(instr);
        char eolChar = eol.charAt(0);
        int i = tgt.length();
        while (true) {
            i--;
            if (i <= 0) {
                return ident + tgt.toString();
            }
            if (tgt.charAt(i) == eolChar) {
                tgt.insert(i + 1, ident);
            }
        }
    }

    public ColorSpace(RandomAccessIO in, HeaderDecoder hd, ParameterList pl) throws IOException, ColorSpaceException {
        this.pl = pl;
        this.in = in;
        this.hd = hd;
        getBoxes();
    }

    protected final void getBoxes() throws ColorSpaceException, IOException {
        long len;
        int boxStart = 0;
        byte[] boxHeader = new byte[16];
        int i = 0;
        while (true) {
            this.in.seek(boxStart);
            this.in.readFully(boxHeader, 0, 16);
            len = (long) ICCProfile.getInt(boxHeader, 0);
            if (len == 1) {
                len = ICCProfile.getLong(boxHeader, 8);
            }
            int type = ICCProfile.getInt(boxHeader, 4);
            if (i == 0 && type != FileFormatBoxes.JP2_SIGNATURE_BOX) {
                throw new ColorSpaceException("first box in image not signature");
            } else if (i == 1 && type != FileFormatBoxes.FILE_TYPE_BOX) {
                throw new ColorSpaceException("second box in image not file");
            } else if (type == FileFormatBoxes.CONTIGUOUS_CODESTREAM_BOX) {
                throw new ColorSpaceException("header box not found in image");
            } else if (type == FileFormatBoxes.JP2_HEADER_BOX) {
                break;
            } else {
                i++;
                boxStart = (int) (((long) boxStart) + len);
            }
        }
        long headerBoxEnd = ((long) boxStart) + len;
        if (len == 1) {
            boxStart += 8;
        }
        boxStart += 8;
        while (((long) boxStart) < headerBoxEnd) {
            this.in.seek(boxStart);
            this.in.readFully(boxHeader, 0, 16);
            len = (long) ICCProfile.getInt(boxHeader, 0);
            if (len == 1) {
                throw new ColorSpaceException("Extended length boxes not supported");
            }
            switch (ICCProfile.getInt(boxHeader, 4)) {
                case FileFormatBoxes.CHANNEL_DEFINITION_BOX /*1667523942*/:
                    this.cdbox = new ChannelDefinitionBox(this.in, boxStart);
                    break;
                case FileFormatBoxes.COMPONENT_MAPPING_BOX /*1668112752*/:
                    this.cmbox = new ComponentMappingBox(this.in, boxStart);
                    break;
                case FileFormatBoxes.COLOUR_SPECIFICATION_BOX /*1668246642*/:
                    this.csbox = new ColorSpecificationBox(this.in, boxStart);
                    break;
                case FileFormatBoxes.IMAGE_HEADER_BOX /*1768449138*/:
                    this.ihbox = new ImageHeaderBox(this.in, boxStart);
                    break;
                case FileFormatBoxes.PALETTE_BOX /*1885564018*/:
                    this.pbox = new PaletteBox(this.in, boxStart);
                    break;
                default:
                    break;
            }
            boxStart = (int) (((long) boxStart) + len);
        }
        if (this.ihbox == null) {
            throw new ColorSpaceException("image header box not found");
        } else if ((this.pbox == null && this.cmbox != null) || (this.pbox != null && this.cmbox == null)) {
            throw new ColorSpaceException("palette box and component mapping box inconsistency");
        }
    }

    public int getChannelDefinition(int c) {
        return this.cdbox == null ? c : this.cdbox.getCn(c + 1);
    }

    public MethodEnum getMethod() {
        return this.csbox.getMethod();
    }

    public CSEnum getColorSpace() {
        return this.csbox.getColorSpace();
    }

    public PaletteBox getPaletteBox() {
        return this.pbox;
    }

    public int getPaletteChannels() {
        return this.pbox == null ? 0 : this.pbox.getNumColumns();
    }

    public int getPaletteChannelBits(int c) {
        return this.pbox == null ? 0 : this.pbox.getBitDepth(c);
    }

    public int getPalettizedSample(int channel, int index) {
        return this.pbox == null ? 0 : this.pbox.getEntry(channel, index);
    }

    public boolean isPalettized() {
        return this.pbox != null;
    }

    public boolean isOutputSigned(int channel) {
        return this.pbox != null ? this.pbox.isSigned(channel) : this.hd.isOriginalSigned(channel);
    }

    public String toString() {
        StringBuffer rep = new StringBuffer("[ColorSpace is ").append(this.csbox.getMethodString()).append(isPalettized() ? "  and palettized " : " ").append(getMethod() == ENUMERATED ? this.csbox.getColorSpaceString() : "");
        if (this.ihbox != null) {
            rep.append(eol).append(indent("    ", this.ihbox.toString()));
        }
        if (this.cdbox != null) {
            rep.append(eol).append(indent("    ", this.cdbox.toString()));
        }
        if (this.csbox != null) {
            rep.append(eol).append(indent("    ", this.csbox.toString()));
        }
        if (this.pbox != null) {
            rep.append(eol).append(indent("    ", this.pbox.toString()));
        }
        if (this.cmbox != null) {
            rep.append(eol).append(indent("    ", this.cmbox.toString()));
        }
        return rep.append("]").toString();
    }

    public boolean debugging() {
        return this.pl.getProperty("colorspace_debug") != null && this.pl.getProperty("colorspace_debug").equalsIgnoreCase("on");
    }
}
