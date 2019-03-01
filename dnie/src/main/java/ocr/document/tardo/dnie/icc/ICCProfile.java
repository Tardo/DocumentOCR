package icc;

import colorspace.ColorSpace;
import colorspace.ColorSpaceException;
import icc.tags.ICCCurveType;
import icc.tags.ICCTagTable;
import icc.tags.ICCXYZType;
import icc.types.ICCDateTime;
import icc.types.ICCProfileHeader;
import icc.types.ICCProfileVersion;
import icc.types.XYZNumber;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Hashtable;
import jj2000.j2k.fileformat.FileFormatBoxes;
import jj2000.j2k.util.FacilityManager;
import jj2000.j2k.util.ParameterList;

public abstract class ICCProfile {
    public static final int BITS_PER_BYTE = 8;
    public static final int BITS_PER_INT = 32;
    public static final int BITS_PER_LONG = 64;
    public static final int BITS_PER_SHORT = 16;
    public static final int BLUE = 2;
    public static final int BYTES_PER_INT = 4;
    public static final int BYTES_PER_LONG = 8;
    public static final int BYTES_PER_SHORT = 2;
    public static final int GRAY = 0;
    public static final int GREEN = 1;
    public static final int RED = 0;
    public static final int boolean_size = 1;
    public static final int byte_size = 1;
    public static final int char_size = 2;
    public static final int double_size = 8;
    private static final String eol = System.getProperty("line.separator");
    public static final int float_size = 4;
    public static final int int_size = 4;
    public static final int kMonochromeInput = 0;
    public static final int kThreeCompInput = 1;
    public static final int kdwBlueColorantTag = getInt(new String("bXYZ").getBytes(), 0);
    public static final int kdwBlueTRCTag = getInt(new String("bTRC").getBytes(), 0);
    public static final int kdwCopyrightTag = getInt(new String("cprt").getBytes(), 0);
    public static final int kdwDisplayProfile = getInt(new String("mntr").getBytes(), 0);
    public static final int kdwGrayData = getInt(new String("GRAY").getBytes(), 0);
    public static final int kdwGrayTRCTag = getInt(new String("kTRC").getBytes(), 0);
    public static final int kdwGreenColorantTag = getInt(new String("gXYZ").getBytes(), 0);
    public static final int kdwGreenTRCTag = getInt(new String("gTRC").getBytes(), 0);
    public static final int kdwInputProfile = getInt(new String("scnr").getBytes(), 0);
    public static final int kdwMediaWhiteTag = getInt(new String("wtpt").getBytes(), 0);
    public static final int kdwProfileDescTag = getInt(new String("desc").getBytes(), 0);
    public static final int kdwProfileSigReverse = getInt(new String("psca").getBytes(), 0);
    public static final int kdwProfileSignature = getInt(new String("acsp").getBytes(), 0);
    public static final int kdwRGBData = getInt(new String("RGB ").getBytes(), 0);
    public static final int kdwRedColorantTag = getInt(new String("rXYZ").getBytes(), 0);
    public static final int kdwRedTRCTag = getInt(new String("rTRC").getBytes(), 0);
    public static final int kdwXYZData = getInt(new String("XYZ ").getBytes(), 0);
    public static final int long_size = 8;
    public static final int short_size = 2;
    private byte[] data = null;
    private ICCProfileHeader header = null;
    private ParameterList pl = null;
    private byte[] profile = null;
    private ICCTagTable tags = null;

    private static class BoxType extends Hashtable {
        private static Hashtable map = new Hashtable();

        private BoxType() {
        }

        static {
            put(FileFormatBoxes.BITS_PER_COMPONENT_BOX, "BITS_PER_COMPONENT_BOX");
            put(FileFormatBoxes.CAPTURE_RESOLUTION_BOX, "CAPTURE_RESOLUTION_BOX");
            put(FileFormatBoxes.CHANNEL_DEFINITION_BOX, "CHANNEL_DEFINITION_BOX");
            put(FileFormatBoxes.COLOUR_SPECIFICATION_BOX, "COLOUR_SPECIFICATION_BOX");
            put(FileFormatBoxes.COMPONENT_MAPPING_BOX, "COMPONENT_MAPPING_BOX");
            put(FileFormatBoxes.CONTIGUOUS_CODESTREAM_BOX, "CONTIGUOUS_CODESTREAM_BOX");
            put(FileFormatBoxes.DEFAULT_DISPLAY_RESOLUTION_BOX, "DEFAULT_DISPLAY_RESOLUTION_BOX");
            put(FileFormatBoxes.FILE_TYPE_BOX, "FILE_TYPE_BOX");
            put(FileFormatBoxes.IMAGE_HEADER_BOX, "IMAGE_HEADER_BOX");
            put(FileFormatBoxes.INTELLECTUAL_PROPERTY_BOX, "INTELLECTUAL_PROPERTY_BOX");
            put(FileFormatBoxes.JP2_HEADER_BOX, "JP2_HEADER_BOX");
            put(FileFormatBoxes.JP2_SIGNATURE_BOX, "JP2_SIGNATURE_BOX");
            put(FileFormatBoxes.PALETTE_BOX, "PALETTE_BOX");
            put(FileFormatBoxes.RESOLUTION_BOX, "RESOLUTION_BOX");
            put(FileFormatBoxes.URL_BOX, "URL_BOX");
            put(FileFormatBoxes.UUID_BOX, "UUID_BOX");
            put(FileFormatBoxes.UUID_INFO_BOX, "UUID_INFO_BOX");
            put(FileFormatBoxes.UUID_LIST_BOX, "UUID_LIST_BOX");
            put(FileFormatBoxes.XML_BOX, "XML_BOX");
        }

        public static void put(int type, String desc) {
            map.put(new Integer(type), desc);
        }

        public static String get(int type) {
            return (String) map.get(new Integer(type));
        }

        public static String colorSpecMethod(int meth) {
            switch (meth) {
                case 1:
                    return "Enumerated Color Space";
                case 2:
                    return "Restricted ICC Profile";
                default:
                    return "Undefined Color Spec Method";
            }
        }
    }

    public static int getIntFromString(String fourChar) {
        return getInt(fourChar.getBytes(), 0);
    }

    public static XYZNumber getXYZNumber(byte[] data, int offset) {
        return new XYZNumber(getInt(data, offset), getInt(data, offset + 4), getInt(data, offset + 8));
    }

    public static ICCProfileVersion getICCProfileVersion(byte[] data, int offset) {
        return new ICCProfileVersion(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
    }

    public static ICCDateTime getICCDateTime(byte[] data, int offset) {
        return new ICCDateTime(getShort(data, offset), getShort(data, offset + 2), getShort(data, offset + 4), getShort(data, offset + 6), getShort(data, offset + 8), getShort(data, offset + 10));
    }

    public static String getString(byte[] bfr, int offset, int length, boolean swap) {
        int start;
        byte[] result = new byte[length];
        int incr = swap ? -1 : 1;
        if (swap) {
            start = (offset + length) - 1;
        } else {
            start = offset;
        }
        int j = start;
        for (int i = 0; i < length; i++) {
            result[i] = bfr[j];
            j += incr;
        }
        return new String(result);
    }

    public static short getShort(byte[] bfr, int off, boolean swap) {
        int tmp0 = bfr[off] & 255;
        int tmp1 = bfr[off + 1] & 255;
        return (short) (swap ? (tmp1 << 8) | tmp0 : (tmp0 << 8) | tmp1);
    }

    public static short getShort(byte[] bfr, int off) {
        return (short) (((bfr[off] & 255) << 8) | (bfr[off + 1] & 255));
    }

    public static byte[] setInt(int d) {
        return setInt(d, new byte[4]);
    }

    public static byte[] setInt(int d, byte[] b) {
        if (b == null) {
            b = new byte[4];
        }
        for (int i = 0; i < 4; i++) {
            b[i] = (byte) (d & 255);
            d >>= 8;
        }
        return b;
    }

    public static byte[] setLong(long d) {
        return setLong(d, new byte[4]);
    }

    public static byte[] setLong(long d, byte[] b) {
        if (b == null) {
            b = new byte[8];
        }
        for (int i = 0; i < 8; i++) {
            b[i] = (byte) ((int) (255 & d));
            d >>= 8;
        }
        return b;
    }

    public static int getInt(byte[] bfr, int off, boolean swap) {
        int tmp0 = getShort(bfr, off, swap) & 65535;
        int tmp1 = getShort(bfr, off + 2, swap) & 65535;
        return swap ? (tmp1 << 16) | tmp0 : (tmp0 << 16) | tmp1;
    }

    public static int getInt(byte[] bfr, int off) {
        return ((getShort(bfr, off) & 65535) << 16) | (getShort(bfr, off + 2) & 65535);
    }

    public static long getLong(byte[] bfr, int off) {
        return (((long) (getInt(bfr, off) & -1)) << 32) | ((long) (getInt(bfr, off + 4) & -1));
    }

    private int getProfileSize() {
        return this.header.dwProfileSize;
    }

    private int getCMMTypeSignature() {
        return this.header.dwCMMTypeSignature;
    }

    private int getProfileClass() {
        return this.header.dwProfileClass;
    }

    private int getColorSpaceType() {
        return this.header.dwColorSpaceType;
    }

    private int getPCSType() {
        return this.header.dwPCSType;
    }

    private int getProfileSignature() {
        return this.header.dwProfileSignature;
    }

    private int getPlatformSignature() {
        return this.header.dwPlatformSignature;
    }

    private int getCMMFlags() {
        return this.header.dwCMMFlags;
    }

    private int getDeviceManufacturer() {
        return this.header.dwDeviceManufacturer;
    }

    private int getDeviceModel() {
        return this.header.dwDeviceModel;
    }

    private int getDeviceAttributes1() {
        return this.header.dwDeviceAttributes1;
    }

    private int getDeviceAttributesReserved() {
        return this.header.dwDeviceAttributesReserved;
    }

    private int getRenderingIntent() {
        return this.header.dwRenderingIntent;
    }

    private int getCreatorSig() {
        return this.header.dwCreatorSig;
    }

    private ICCProfileVersion getProfileVersion() {
        return this.header.profileVersion;
    }

    private void setProfileSignature(int profilesig) {
        this.header.dwProfileSignature = profilesig;
    }

    private void setProfileSize(int size) {
        this.header.dwProfileSize = size;
    }

    private void setCMMTypeSignature(int cmmsig) {
        this.header.dwCMMTypeSignature = cmmsig;
    }

    private void setProfileClass(int pclass) {
        this.header.dwProfileClass = pclass;
    }

    private void setColorSpaceType(int colorspace) {
        this.header.dwColorSpaceType = colorspace;
    }

    private void setPCSIlluminant(XYZNumber xyz) {
        this.header.PCSIlluminant = xyz;
    }

    private void setPCSType(int PCStype) {
        this.header.dwPCSType = PCStype;
    }

    private void setPlatformSignature(int platformsig) {
        this.header.dwPlatformSignature = platformsig;
    }

    private void setCMMFlags(int cmmflags) {
        this.header.dwCMMFlags = cmmflags;
    }

    private void setDeviceManufacturer(int manufacturer) {
        this.header.dwDeviceManufacturer = manufacturer;
    }

    private void setDeviceModel(int model) {
        this.header.dwDeviceModel = model;
    }

    private void setDeviceAttributes1(int attr1) {
        this.header.dwDeviceAttributes1 = attr1;
    }

    private void setDeviceAttributesReserved(int attrreserved) {
        this.header.dwDeviceAttributesReserved = attrreserved;
    }

    private void setRenderingIntent(int rendering) {
        this.header.dwRenderingIntent = rendering;
    }

    private void setCreatorSig(int creatorsig) {
        this.header.dwCreatorSig = creatorsig;
    }

    private void setProfileVersion(ICCProfileVersion version) {
        this.header.profileVersion = version;
    }

    private void setDateTime(ICCDateTime datetime) {
        this.header.dateTime = datetime;
    }

    private ICCProfile() throws ICCProfileException {
        throw new ICCProfileException("illegal to invoke empty constructor");
    }

    protected ICCProfile(ColorSpace csm) throws ColorSpaceException, ICCProfileInvalidException {
        this.pl = csm.pl;
        this.profile = csm.getICCProfile();
        initProfile(this.profile);
    }

    private void initProfile(byte[] data) throws ICCProfileInvalidException {
        this.header = new ICCProfileHeader(data);
        this.tags = ICCTagTable.createInstance(data);
        if (getProfileClass() == kdwDisplayProfile) {
            FacilityManager.getMsgLogger().printmsg(2, "NOTE!! Technically, this profile is a Display profile, not an Input Profile, and thus is not a valid Restricted ICC profile. However, it is quite possible that this profile is usable as a Restricted ICC profile, so this code will ignore this state and proceed with processing.");
        }
        if (getProfileSignature() != kdwProfileSignature || ((getProfileClass() != kdwInputProfile && getProfileClass() != kdwDisplayProfile) || getPCSType() != kdwXYZData)) {
            throw new ICCProfileInvalidException();
        }
    }

    public String toString() {
        StringBuffer rep = new StringBuffer("[ICCProfile:");
        StringBuffer body = new StringBuffer();
        body.append(eol).append(this.header);
        body.append(eol).append(eol).append(this.tags);
        rep.append(ColorSpace.indent("  ", body));
        return rep.append("]").toString();
    }

    public static String toHexString(byte i) {
        StringBuilder stringBuilder = new StringBuilder();
        String str = (i < (byte) 0 || i >= (byte) 16) ? "" : "0";
        String rep = stringBuilder.append(str).append(Integer.toHexString(i)).toString();
        if (rep.length() > 2) {
            return rep.substring(rep.length() - 2);
        }
        return rep;
    }

    public static String toHexString(short i) {
        String rep;
        if (i >= (short) 0 && i < (short) 16) {
            rep = "000" + Integer.toHexString(i);
        } else if (i >= (short) 0 && i < (short) 256) {
            rep = "00" + Integer.toHexString(i);
        } else if (i < (short) 0 || i >= (short) 4096) {
            rep = "" + Integer.toHexString(i);
        } else {
            rep = "0" + Integer.toHexString(i);
        }
        if (rep.length() > 4) {
            return rep.substring(rep.length() - 4);
        }
        return rep;
    }

    public static String toHexString(int i) {
        String rep;
        if (i >= 0 && i < 16) {
            rep = "0000000" + Integer.toHexString(i);
        } else if (i >= 0 && i < 256) {
            rep = "000000" + Integer.toHexString(i);
        } else if (i >= 0 && i < 4096) {
            rep = "00000" + Integer.toHexString(i);
        } else if (i >= 0 && i < 65536) {
            rep = "0000" + Integer.toHexString(i);
        } else if (i >= 0 && i < 1048576) {
            rep = "000" + Integer.toHexString(i);
        } else if (i >= 0 && i < 16777216) {
            rep = "00" + Integer.toHexString(i);
        } else if (i < 0 || i >= 268435456) {
            rep = "" + Integer.toHexString(i);
        } else {
            rep = "0" + Integer.toHexString(i);
        }
        if (rep.length() > 8) {
            return rep.substring(rep.length() - 8);
        }
        return rep;
    }

    public static String toString(byte[] data) {
        StringBuffer rep1;
        StringBuffer rep2;
        int i;
        byte[] tbytes;
        int l;
        StringBuffer rep0;
        int col;
        int i2;
        StringBuffer rep = new StringBuffer();
        int rows = data.length / 16;
        int rem = data.length % 16;
        byte[] lbytes = new byte[8];
        int row = 0;
        while (row < rows) {
            rep1 = new StringBuffer();
            rep2 = new StringBuffer();
            i = 0;
            while (i < 8) {
                lbytes[i] = (byte) 0;
                i++;
            }
            tbytes = Integer.toHexString(row * 16).getBytes();
            l = lbytes.length - tbytes.length;
            for (byte b : tbytes) {
                lbytes[l] = b;
                l++;
            }
            rep0 = new StringBuffer(new String(lbytes));
            col = 0;
            i2 = i;
            while (col < 16) {
                i = i2 + 1;
                byte b2 = data[i2];
                rep1.append(toHexString(b2)).append(i % 2 == 0 ? " " : "");
                if (Character.isJavaIdentifierStart((char) b2)) {
                    rep2.append((char) b2);
                } else {
                    rep2.append(".");
                }
                col++;
                i2 = i;
            }
            rep.append(rep0).append(" :  ").append(rep1).append(":  ").append(rep2).append(eol);
            row++;
            i = i2;
        }
        rep1 = new StringBuffer();
        rep2 = new StringBuffer();
        i = 0;
        while (i < 8) {
            lbytes[i] = (byte) 0;
            i++;
        }
        tbytes = Integer.toHexString(row * 16).getBytes();
        l = lbytes.length - tbytes.length;
        for (byte b3 : tbytes) {
            lbytes[l] = b3;
            l++;
        }
        rep0 = new StringBuffer(new String(lbytes));
        col = 0;
        i2 = i;
        while (col < rem) {
            i = i2 + 1;
            b2 = data[i2];
            rep1.append(toHexString(b2)).append(i % 2 == 0 ? " " : "");
            if (Character.isJavaIdentifierStart((char) b2)) {
                rep2.append((char) b2);
            } else {
                rep2.append(".");
            }
            col++;
            i2 = i;
        }
        for (col = rem; col < 16; col++) {
            rep1.append("  ").append(col % 2 == 0 ? " " : "");
        }
        rep.append(rep0).append(" :  ").append(rep1).append(":  ").append(rep2).append(eol);
        return rep.toString();
    }

    public ICCProfileHeader getHeader() {
        return this.header;
    }

    public ICCTagTable getTagTable() {
        return this.tags;
    }

    public RestrictedICCProfile parse() throws ICCProfileInvalidException {
        ICCCurveType grayTag = (ICCCurveType) this.tags.get(new Integer(kdwGrayTRCTag));
        if (grayTag != null) {
            return RestrictedICCProfile.createInstance(grayTag);
        }
        ICCCurveType rTRCTag = (ICCCurveType) this.tags.get(new Integer(kdwRedTRCTag));
        if (rTRCTag != null) {
            return RestrictedICCProfile.createInstance(rTRCTag, (ICCCurveType) this.tags.get(new Integer(kdwGreenTRCTag)), (ICCCurveType) this.tags.get(new Integer(kdwBlueTRCTag)), (ICCXYZType) this.tags.get(new Integer(kdwRedColorantTag)), (ICCXYZType) this.tags.get(new Integer(kdwGreenColorantTag)), (ICCXYZType) this.tags.get(new Integer(kdwBlueColorantTag)));
        }
        throw new ICCProfileInvalidException("curve data not found in profile");
    }

    public void write(RandomAccessFile os) throws IOException {
        getHeader().write(os);
        getTagTable().write(os);
    }
}
