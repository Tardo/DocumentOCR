package jj2000.j2k.decoder;

import colorspace.ColorSpace;
import colorspace.ColorSpaceMapper;
import java.lang.reflect.Array;
import java.util.Enumeration;
import java.util.Vector;
import jj2000.j2k.codestream.HeaderInfo;
import jj2000.j2k.codestream.reader.BitstreamReaderAgent;
import jj2000.j2k.codestream.reader.HeaderDecoder;
import jj2000.j2k.entropy.decoder.EntropyDecoder;
import jj2000.j2k.image.invcomptransf.InvCompTransf;
import jj2000.j2k.quantization.dequantizer.Dequantizer;
import jj2000.j2k.roi.ROIDeScaler;
import jj2000.j2k.util.ParameterList;
import jj2000.j2k.util.StringFormatException;

public class Grib2JpegDecoder {
    private static final String[][] pinfo;
    private static final char[] vprfxs = new char[]{BitstreamReaderAgent.OPT_PREFIX, EntropyDecoder.OPT_PREFIX, 'R', Dequantizer.OPT_PREFIX, InvCompTransf.OPT_PREFIX, HeaderDecoder.OPT_PREFIX, 'I'};
    private ColorSpace csMap = null;
    public int[] data;
    private ParameterList defpl = new ParameterList();
    private int exitCode;
    private HeaderInfo hi;
    private boolean isChildProcess = false;
    private int packBytes;
    private ParameterList pl;

    static {
        r0 = new String[20][];
        r0[0] = new String[]{"u", "[on|off]", "Prints usage information. If specified all other arguments (except 'v') are ignored", "off"};
        r0[1] = new String[]{"v", "[on|off]", "Prints version and copyright information", "off"};
        r0[2] = new String[]{"verbose", "[on|off]", "Prints information about the decoded codestream", "on"};
        r0[3] = new String[]{"pfile", "<filename>", "Loads the arguments from the specified file. Arguments that are specified on the command line override the ones from the file.\nThe arguments file is a simple text file with one argument per line of the following form:\n  <argument name>=<argument value>\nIf the argument is of boolean type (i.e. its presence turns a feature on), then the 'on' value turns it on, while the 'off' value turns it off. The argument name does not include the '-' or '+' character. Long lines can be broken into several lines by terminating them with '\\'. Lines starting with '#' are considered as comments. This option is not recursive: any 'pfile' argument appearing in the file is ignored.", null};
        r0[4] = new String[]{"res", "<resolution level index>", "The resolution level at which to reconstruct the image  (0 means the lowest available resolution whereas the maximum resolution level corresponds to the original image resolution). If the given index is greater than the number of available resolution levels of the compressed image, the image is reconstructed at its highest resolution (among all tile-components). Note that this option affects only the inverse wavelet transform and not the number  of bytes read by the codestream parser: this number of bytes depends only on options '-nbytes' or '-rate'.", null};
        r0[5] = new String[]{"i", "<filename or url>", "The file containing the JPEG 2000 compressed data. This can be either a JPEG 2000 codestream or a JP2 file containing a JPEG 2000 codestream. In the latter case the first codestream in the file will be decoded. If an URL is specified (e.g., http://...) the data will be downloaded and cached in memory before decoding. This is intended for easy use in applets, but it is not a very efficient way of decoding network served data.", null};
        r0[6] = new String[]{"o", "<filename>", "This is the name of the file to which the decompressed image is written. If no output filename is given, the image is displayed on the screen. Output file format is PGX by default. If the extension is '.pgm' then a PGM file is written as output, however this is only permitted if the component bitdepth does not exceed 8. If the extension is '.ppm' then a PPM file is written, however this is only permitted if there are 3 components and none of them has a bitdepth of more than 8. If there is more than 1 component, suffices '-1', '-2', '-3', ... are added to the file name, just before the extension, except for PPM files where all three components are written to the same file.", null};
        r0[7] = new String[]{"rate", "<decoding rate in bpp>", "Specifies the decoding rate in bits per pixel (bpp) where the number of pixels is related to the image's original size (Note: this number is not affected by the '-res' option). If it is equalto -1, the whole codestream is decoded. The codestream is either parsed (default) or truncated depending the command line option '-parsing'. To specify the decoding rate in bytes, use '-nbytes' options instead.", "-1"};
        r0[8] = new String[]{"nbytes", "<decoding rate in bytes>", "Specifies the decoding rate in bytes. The codestream is either parsed (default) or truncated depending the command line option '-parsing'. To specify the decoding rate in bits per pixel, use '-rate' options instead.", "-1"};
        r0[9] = new String[]{"parsing", null, "Enable or not the parsing mode when decoding rate is specified ('-nbytes' or '-rate' options). If it is false, the codestream is decoded as if it were truncated to the given rate. If it is true, the decoder creates, truncates and decodes a virtual layer progressive codestream with the same truncation points in each code-block.", "on"};
        r0[10] = new String[]{"ncb_quit", "<max number of code blocks>", "Use the ncb and lbody quit conditions. If state information is found for more code blocks than is indicated with this option, the decoder will decode using only information found before that point. Using this otion implies that the 'rate' or 'nbyte' parameter is used to indicate the lbody parameter which is the number of packet body bytes the decoder will decode.", "-1"};
        r0[11] = new String[]{"l_quit", "<max number of layers>", "Specifies the maximum number of layers to decode for any code-block", "-1"};
        r0[12] = new String[]{"m_quit", "<max number of bit planes>", "Specifies the maximum number of bit planes to decode for any code-block", "-1"};
        r0[13] = new String[]{"poc_quit", null, "Specifies the whether the decoder should only decode code-blocks included in the first progression order.", "off"};
        r0[14] = new String[]{"one_tp", null, "Specifies whether the decoder should only decode the first tile part of each tile.", "off"};
        r0[15] = new String[]{"comp_transf", null, "Specifies whether the component transform indicated in the codestream should be used.", "on"};
        r0[16] = new String[]{"debug", null, "Print debugging messages when an error is encountered.", "off"};
        r0[17] = new String[]{"cdstr_info", null, "Display information about the codestream. This information is: \n- Marker segments value in main and tile-part headers,\n- Tile-part length and position within the code-stream.", "off"};
        r0[18] = new String[]{"nocolorspace", null, "Ignore any colorspace information in the image.", "off"};
        r0[19] = new String[]{"colorspace_debug", null, "Print debugging messages when an error is encountered in the colorspace module.", "off"};
        pinfo = r0;
    }

    public Grib2JpegDecoder(String[] argv) {
        String[][] param = getAllParameters();
        for (int i = param.length - 1; i >= 0; i--) {
            if (param[i][3] != null) {
                this.defpl.put(param[i][0], param[i][3]);
            }
        }
        this.pl = new ParameterList(this.defpl);
        if (argv.length == 0) {
            throw new IllegalArgumentException("No arguments!");
        }
        try {
            this.pl.parseArgs(argv);
        } catch (StringFormatException e) {
            System.err.println("An error occured while parsing the arguments:\n" + e.getMessage());
        }
    }

    public int getExitCode() {
        return this.exitCode;
    }

    public static String[][] getParameterInfo() {
        return pinfo;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void decode(ucar.unidata.io.RandomAccessFile r47, int r48) {
        /*
        r46 = this;
        r25 = 0;
        r5 = 0;
        r0 = r46;
        r4 = r0.pl;	 Catch:{ StringFormatException -> 0x0113, NumberFormatException -> 0x019c }
        r6 = "v";
        r4 = r4.getBooleanParameter(r6);	 Catch:{ StringFormatException -> 0x0113, NumberFormatException -> 0x019c }
        if (r4 == 0) goto L_0x0012;
    L_0x000f:
        r46.printVersionAndCopyright();	 Catch:{ StringFormatException -> 0x0113, NumberFormatException -> 0x019c }
    L_0x0012:
        r0 = r46;
        r4 = r0.pl;	 Catch:{ StringFormatException -> 0x0113, NumberFormatException -> 0x019c }
        r6 = "u";
        r4 = r4.getParameter(r6);	 Catch:{ StringFormatException -> 0x0113, NumberFormatException -> 0x019c }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ StringFormatException -> 0x0113, NumberFormatException -> 0x019c }
        if (r4 == 0) goto L_0x0028;
    L_0x0024:
        r46.printUsage();	 Catch:{ StringFormatException -> 0x0113, NumberFormatException -> 0x019c }
    L_0x0027:
        return;
    L_0x0028:
        r0 = r46;
        r4 = r0.pl;	 Catch:{ StringFormatException -> 0x0113, NumberFormatException -> 0x019c }
        r6 = "verbose";
        r41 = r4.getBooleanParameter(r6);	 Catch:{ StringFormatException -> 0x0113, NumberFormatException -> 0x019c }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0236, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = vprfxs;	 Catch:{ IllegalArgumentException -> 0x0236, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r7 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0236, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = pinfo;	 Catch:{ IllegalArgumentException -> 0x0236, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = jj2000.j2k.util.ParameterList.toNameArray(r7);	 Catch:{ IllegalArgumentException -> 0x0236, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.checkList(r6, r7);	 Catch:{ IllegalArgumentException -> 0x0236, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r48;
        r11 = new byte[r0];	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r47;
        r0.read(r11);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r8 = new java.io.ByteArrayInputStream;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r8.<init>(r11);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r2 = new jj2000.j2k.util.ISRandomAccessIO;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = 1;
        r0 = r48;
        r1 = r48;
        r2.<init>(r8, r0, r4, r1);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r21 = new jj2000.j2k.fileformat.reader.FileFormatReader;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r21;
        r0.<init>(r2);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r21.readFileFormat();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r21;
        r4 = r0.JP2FFUsed;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x0074;
    L_0x006d:
        r4 = r21.getFirstCodeStreamPos();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r2.seek(r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x0074:
        r4 = new jj2000.j2k.codestream.HeaderInfo;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r0.hi = r4;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r3 = new jj2000.j2k.codestream.reader.HeaderDecoder;	 Catch:{ EOFException -> 0x0262 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ EOFException -> 0x0262 }
        r0 = r46;
        r6 = r0.hi;	 Catch:{ EOFException -> 0x0262 }
        r3.<init>(r2, r4, r6);	 Catch:{ EOFException -> 0x0262 }
        r32 = r3.getNumComps();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.siz;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r34 = r4.getNumTiles();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r5 = r3.getDecoderSpecs();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r41 == 0) goto L_0x02de;
    L_0x009e:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r32;
        r4 = r4.append(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = " component(s) in codestream, ";
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r34;
        r4 = r4.append(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = " tile(s)\n";
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r26 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r26;
        r4 = r4.append(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "Image dimension: ";
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r26 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r12 = 0;
    L_0x00d5:
        r0 = r32;
        if (r12 >= r0) goto L_0x028c;
    L_0x00d9:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r26;
        r4 = r4.append(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r6 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.siz;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.getCompImgWidth(r12);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "x";
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r6 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.siz;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.getCompImgHeight(r12);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = " ";
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r26 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r12 = r12 + 1;
        goto L_0x00d5;
    L_0x0113:
        r19 = move-exception;
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "An error occured while parsing the arguments:\n";
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 1;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x016a;
    L_0x0143:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0148:
        r19 = move-exception;
        r4 = r19.getMessage();
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);
        r0 = r46;
        r4 = r0.pl;
        r6 = "debug";
        r4 = r4.getParameter(r6);
        r6 = "on";
        r4 = r4.equals(r6);
        if (r4 == 0) goto L_0x0027;
    L_0x0165:
        r19.printStackTrace();
        goto L_0x0027;
    L_0x016a:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0174:
        r19 = move-exception;
        r4 = r19.getMessage();
        if (r4 == 0) goto L_0x08fe;
    L_0x017b:
        r4 = r19.getMessage();
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);
    L_0x0185:
        r0 = r46;
        r4 = r0.pl;
        r6 = "debug";
        r4 = r4.getParameter(r6);
        r6 = "on";
        r4 = r4.equals(r6);
        if (r4 == 0) goto L_0x0908;
    L_0x0197:
        r19.printStackTrace();
        goto L_0x0027;
    L_0x019c:
        r19 = move-exception;
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "An error occured while parsing the arguments:\n";
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 1;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x020c;
    L_0x01cc:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x01d1:
        r19 = move-exception;
        r4 = r19.getMessage();
        if (r4 == 0) goto L_0x0912;
    L_0x01d8:
        r4 = new java.lang.StringBuilder;
        r4.<init>();
        r6 = "An uncaught runtime exception has occurred:\n";
        r4 = r4.append(r6);
        r6 = r19.getMessage();
        r4 = r4.append(r6);
        r4 = r4.toString();
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);
    L_0x01f5:
        r0 = r46;
        r4 = r0.pl;
        r6 = "debug";
        r4 = r4.getParameter(r6);
        r6 = "on";
        r4 = r4.equals(r6);
        if (r4 == 0) goto L_0x091c;
    L_0x0207:
        r19.printStackTrace();
        goto L_0x0027;
    L_0x020c:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0216:
        r19 = move-exception;
        r4 = "An uncaught exception has occurred.";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);
        r0 = r46;
        r4 = r0.pl;
        r6 = "debug";
        r4 = r4.getParameter(r6);
        r6 = "on";
        r4 = r4.equals(r6);
        if (r4 == 0) goto L_0x0926;
    L_0x0231:
        r19.printStackTrace();
        goto L_0x0027;
    L_0x0236:
        r19 = move-exception;
        r4 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x0258;
    L_0x0253:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0258:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0262:
        r19 = move-exception;
        r4 = "Codestream too short or bad header, unable to decode.";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x0282;
    L_0x027d:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0282:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x028c:
        r4 = 1;
        r0 = r34;
        if (r0 == r4) goto L_0x02c4;
    L_0x0291:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r26;
        r4 = r4.append(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "\nNom. Tile dim. (in canvas): ";
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r6 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.siz;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.xtsiz;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "x";
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r6 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.siz;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.ytsiz;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r26 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x02c4:
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "[INFO]: ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r26;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x02de:
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "cdstr_info";
        r4 = r4.getBooleanParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x030a;
    L_0x02ea:
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "[INFO]: Main header:\n";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r7 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r7.toStringMainHeader();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x030a:
        r0 = r32;
        r0 = new int[r0];	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r17 = r0;
        r22 = 0;
    L_0x0312:
        r0 = r22;
        r1 = r32;
        if (r0 >= r1) goto L_0x0323;
    L_0x0318:
        r0 = r22;
        r4 = r3.getOriginalBitDepth(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r17[r22] = r4;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r22 = r22 + 1;
        goto L_0x0312;
    L_0x0323:
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IOException -> 0x0573, IllegalArgumentException -> 0x05ce, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r6 = r0.pl;	 Catch:{ IOException -> 0x0573, IllegalArgumentException -> 0x05ce, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "cdstr_info";
        r6 = r6.getBooleanParameter(r7);	 Catch:{ IOException -> 0x0573, IllegalArgumentException -> 0x05ce, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r7 = r0.hi;	 Catch:{ IOException -> 0x0573, IllegalArgumentException -> 0x05ce, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r10 = jj2000.j2k.codestream.reader.BitstreamReaderAgent.createInstance(r2, r3, r4, r5, r6, r7);	 Catch:{ IOException -> 0x0573, IllegalArgumentException -> 0x05ce, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0629, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r20 = r3.createEntropyDecoder(r10, r4);	 Catch:{ IllegalArgumentException -> 0x0629, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0684, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r20;
        r39 = r3.createROIDeScaler(r0, r4, r5);	 Catch:{ IllegalArgumentException -> 0x0684, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r39;
        r1 = r17;
        r18 = r3.createDequantizer(r0, r1, r5);	 Catch:{ IllegalArgumentException -> 0x06df, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r18;
        r27 = jj2000.j2k.wavelet.synthesis.InverseWT.createInstance(r0, r5);	 Catch:{ IllegalArgumentException -> 0x073a, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r37 = r10.getImgRes();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r27;
        r1 = r37;
        r0.setImgResLevel(r1);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r15 = new jj2000.j2k.image.ImgDataConverter;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = 0;
        r0 = r27;
        r15.<init>(r0, r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r23 = new jj2000.j2k.image.invcomptransf.InvCompTransf;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r23;
        r1 = r17;
        r0.<init>(r15, r5, r1, r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r21;
        r4 = r0.JP2FFUsed;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x0811;
    L_0x037f:
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "nocolorspace";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "off";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x0811;
    L_0x0391:
        r4 = new colorspace.ColorSpace;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>(r2, r3, r6);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r0.csMap = r4;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r23;
        r13 = r3.createChannelDefinitionMapper(r0, r4);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r38 = r3.createResampler(r13, r4);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r38;
        r36 = r3.createPalettizedColorSpaceMapper(r0, r4);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r36;
        r14 = r3.createColorSpaceMapper(r0, r4);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.debugging();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x044e;
    L_0x03ce:
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "[ERROR]: ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r7 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "[ERROR]: ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.append(r13);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "[ERROR]: ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r38;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "[ERROR]: ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r36;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "[ERROR]: ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.append(r14);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0795, ColorSpaceException -> 0x07d3, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x044e:
        r16 = r14;
        if (r14 != 0) goto L_0x0454;
    L_0x0452:
        r16 = r23;
    L_0x0454:
        r33 = r16.getNumComps();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r5.dls;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r31 = r4.getMin();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r41 == 0) goto L_0x04f2;
    L_0x0460:
        r0 = r31;
        r1 = r37;
        if (r0 == r1) goto L_0x04b2;
    L_0x0466:
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "Reconstructing resolution ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r37;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = " on ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r31;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = " (";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r37;
        r7 = r10.getImgWidth(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "x";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r37;
        r7 = r10.getImgHeight(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = ")";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x04b2:
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "rate";
        r4 = r4.getFloatParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = -1082130432; // 0xffffffffbf800000 float:-1.0 double:NaN;
        r4 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1));
        if (r4 == 0) goto L_0x04f2;
    L_0x04c2:
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "Target rate = ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r10.getTargetRate();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = " bpp (";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r10.getTargetNbytes();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = " bytes)";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x04f2:
        r0 = r33;
        r0 = new jj2000.j2k.image.output.ImgWriter[r0];	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r25 = r0;
        r28 = 0;
        r22 = 0;
    L_0x04fc:
        r0 = r25;
        r4 = r0.length;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r22;
        if (r0 >= r4) goto L_0x087e;
    L_0x0503:
        r0 = r46;
        r4 = r0.csMap;	 Catch:{ IOException -> 0x082e }
        if (r4 == 0) goto L_0x0815;
    L_0x0509:
        r0 = r46;
        r4 = r0.csMap;	 Catch:{ IOException -> 0x082e }
        r0 = r22;
        r28 = r4.isOutputSigned(r0);	 Catch:{ IOException -> 0x082e }
        r4 = new jj2000.j2k.image.output.ImgWriterArray;	 Catch:{ IOException -> 0x082e }
        r0 = r46;
        r6 = r0.csMap;	 Catch:{ IOException -> 0x082e }
        r0 = r22;
        r6 = r6.isOutputSigned(r0);	 Catch:{ IOException -> 0x082e }
        r0 = r16;
        r1 = r22;
        r4.<init>(r0, r1, r6);	 Catch:{ IOException -> 0x082e }
        r25[r22] = r4;	 Catch:{ IOException -> 0x082e }
    L_0x0528:
        r4 = r25[r22];	 Catch:{ IOException -> 0x085c }
        r4.writeAll();	 Catch:{ IOException -> 0x085c }
        r29 = r25[r22];	 Catch:{ IOException -> 0x085c }
        r29 = (jj2000.j2k.image.output.ImgWriterArray) r29;	 Catch:{ IOException -> 0x085c }
        r4 = r29.getGdata();	 Catch:{ IOException -> 0x085c }
        r0 = r46;
        r0.data = r4;	 Catch:{ IOException -> 0x085c }
        if (r28 != 0) goto L_0x0850;
    L_0x053b:
        r6 = 4611686018427387904; // 0x4000000000000000 float:0.0 double:2.0;
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IOException -> 0x085c }
        r42 = "rate";
        r0 = r42;
        r4 = r4.getFloatParameter(r0);	 Catch:{ IOException -> 0x085c }
        r0 = (double) r4;	 Catch:{ IOException -> 0x085c }
        r42 = r0;
        r44 = 4607182418800017408; // 0x3ff0000000000000 float:0.0 double:1.0;
        r42 = r42 - r44;
        r0 = r42;
        r6 = java.lang.Math.pow(r6, r0);	 Catch:{ IOException -> 0x085c }
        r0 = (float) r6;	 Catch:{ IOException -> 0x085c }
        r40 = r0;
        r30 = 0;
    L_0x055b:
        r0 = r46;
        r4 = r0.data;	 Catch:{ IOException -> 0x085c }
        r4 = r4.length;	 Catch:{ IOException -> 0x085c }
        r0 = r30;
        if (r0 >= r4) goto L_0x0850;
    L_0x0564:
        r0 = r46;
        r4 = r0.data;	 Catch:{ IOException -> 0x085c }
        r6 = r4[r30];	 Catch:{ IOException -> 0x085c }
        r6 = (float) r6;	 Catch:{ IOException -> 0x085c }
        r6 = r6 + r40;
        r6 = (int) r6;	 Catch:{ IOException -> 0x085c }
        r4[r30] = r6;	 Catch:{ IOException -> 0x085c }
        r30 = r30 + 1;
        goto L_0x055b;
    L_0x0573:
        r19 = move-exception;
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "Error while reading bit stream header or parsing packets";
        r6 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x05c1;
    L_0x0585:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = ":\n";
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x059c:
        r4 = r6.append(r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 4;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x05c4;
    L_0x05bc:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x05c1:
        r4 = "";
        goto L_0x059c;
    L_0x05c4:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x05ce:
        r19 = move-exception;
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "Cannot instantiate bit stream reader";
        r6 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x061c;
    L_0x05e0:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = ":\n";
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x05f7:
        r4 = r6.append(r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x061f;
    L_0x0617:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x061c:
        r4 = "";
        goto L_0x05f7;
    L_0x061f:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0629:
        r19 = move-exception;
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "Cannot instantiate entropy decoder";
        r6 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x0677;
    L_0x063b:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = ":\n";
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x0652:
        r4 = r6.append(r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x067a;
    L_0x0672:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0677:
        r4 = "";
        goto L_0x0652;
    L_0x067a:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0684:
        r19 = move-exception;
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "Cannot instantiate roi de-scaler.";
        r6 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x06d2;
    L_0x0696:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = ":\n";
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x06ad:
        r4 = r6.append(r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x06d5;
    L_0x06cd:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x06d2:
        r4 = "";
        goto L_0x06ad;
    L_0x06d5:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x06df:
        r19 = move-exception;
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "Cannot instantiate dequantizer";
        r6 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x072d;
    L_0x06f1:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = ":\n";
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x0708:
        r4 = r6.append(r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x0730;
    L_0x0728:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x072d:
        r4 = "";
        goto L_0x0708;
    L_0x0730:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x073a:
        r19 = move-exception;
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "Cannot instantiate inverse wavelet transform";
        r6 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x0788;
    L_0x074c:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = ":\n";
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x0763:
        r4 = r6.append(r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x078b;
    L_0x0783:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0788:
        r4 = "";
        goto L_0x0763;
    L_0x078b:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0795:
        r19 = move-exception;
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "Could not instantiate ICC profiler";
        r6 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x07d0;
    L_0x07a7:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = ":\n";
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x07be:
        r4 = r6.append(r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 1;
        r0 = r46;
        r1 = r19;
        r0.error(r4, r6, r1);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x07d0:
        r4 = "";
        goto L_0x07be;
    L_0x07d3:
        r19 = move-exception;
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "error processing jp2 colorspace information";
        r6 = r4.append(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x080e;
    L_0x07e5:
        r4 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = ": ";
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = r19.getMessage();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
    L_0x07fc:
        r4 = r6.append(r4);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 1;
        r0 = r46;
        r1 = r19;
        r0.error(r4, r6, r1);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x080e:
        r4 = "    ";
        goto L_0x07fc;
    L_0x0811:
        r14 = r23;
        goto L_0x044e;
    L_0x0815:
        r0 = r22;
        r28 = r3.isOriginalSigned(r0);	 Catch:{ IOException -> 0x082e }
        r4 = new jj2000.j2k.image.output.ImgWriterArray;	 Catch:{ IOException -> 0x082e }
        r0 = r22;
        r6 = r3.isOriginalSigned(r0);	 Catch:{ IOException -> 0x082e }
        r0 = r16;
        r1 = r22;
        r4.<init>(r0, r1, r6);	 Catch:{ IOException -> 0x082e }
        r25[r22] = r4;	 Catch:{ IOException -> 0x082e }
        goto L_0x0528;
    L_0x082e:
        r19 = move-exception;
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x0846;
    L_0x0841:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0846:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0850:
        r4 = r29.getPackBytes();	 Catch:{ IOException -> 0x085c }
        r0 = r46;
        r0.packBytes = r4;	 Catch:{ IOException -> 0x085c }
        r22 = r22 + 1;
        goto L_0x04fc;
    L_0x085c:
        r19 = move-exception;
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "debug";
        r4 = r4.getParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "on";
        r4 = r4.equals(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x0874;
    L_0x086f:
        r19.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x0874:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x087e:
        if (r41 == 0) goto L_0x0027;
    L_0x0880:
        r9 = r10.getActualRate();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r35 = r10.getActualNbytes();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r21;
        r4 = r0.JP2FFUsed;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        if (r4 == 0) goto L_0x08a9;
    L_0x088e:
        r4 = 1090519040; // 0x41000000 float:8.0 double:5.38787994E-315;
        r0 = r35;
        r6 = (float) r0;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4 = r4 * r6;
        r4 = r4 / r9;
        r0 = (int) r4;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r24 = r0;
        r4 = r21.getFirstCodeStreamPos();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r35 = r35 + r4;
        r0 = r35;
        r4 = (float) r0;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = 1090519040; // 0x41000000 float:8.0 double:5.38787994E-315;
        r4 = r4 * r6;
        r0 = r24;
        r6 = (float) r0;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r9 = r4 / r6;
    L_0x08a9:
        r0 = r46;
        r4 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = "ncb_quit";
        r4 = r4.getIntParameter(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = -1;
        if (r4 != r6) goto L_0x08e2;
    L_0x08b6:
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "Actual bit rate = ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = " bpp (i.e. ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r35;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = " bytes)";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x08e2:
        r4 = java.lang.System.out;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r7 = "Number of packet body bytes read = ";
        r6 = r6.append(r7);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r0 = r35;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        r4.println(r6);	 Catch:{ IllegalArgumentException -> 0x0148, Error -> 0x0174, RuntimeException -> 0x01d1, Throwable -> 0x0216 }
        goto L_0x0027;
    L_0x08fe:
        r4 = "An error has occured during decoding.";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);
        goto L_0x0185;
    L_0x0908:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);
        goto L_0x0027;
    L_0x0912:
        r4 = "An uncaught runtime exception has occurred.";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);
        goto L_0x01f5;
    L_0x091c:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);
        goto L_0x0027;
    L_0x0926:
        r4 = "Use '-debug' option for more details";
        r6 = 2;
        r0 = r46;
        r0.error(r4, r6);
        goto L_0x0027;
        */
        throw new UnsupportedOperationException("Method not decompiled: jj2000.j2k.decoder.Grib2JpegDecoder.decode(ucar.unidata.io.RandomAccessFile, int):void");
    }

    private void error(String msg, int code) {
        this.exitCode = code;
        System.out.println(msg);
    }

    private void error(String msg, int code, Throwable ex) {
        this.exitCode = code;
        System.out.println(msg);
        if (this.pl.getParameter("debug").equals("on")) {
            ex.printStackTrace();
        } else {
            error("Use '-debug' option for more details", 2);
        }
    }

    public int getPackBytes() {
        return this.packBytes;
    }

    public int[] getGdata() {
        return this.data;
    }

    public String[] getCOMInfo() {
        if (this.hi == null) {
            return null;
        }
        int nCOMMarkers = this.hi.getNumCOM();
        Enumeration com = this.hi.com.elements();
        String[] infoCOM = new String[nCOMMarkers];
        for (int i = 0; i < nCOMMarkers; i++) {
            infoCOM[i] = com.nextElement().toString();
        }
        return infoCOM;
    }

    public static String[][] getAllParameters() {
        int i;
        Vector vec = new Vector();
        String[][] str = BitstreamReaderAgent.getParameterInfo();
        if (str != null) {
            for (i = str.length - 1; i >= 0; i--) {
                vec.addElement(str[i]);
            }
        }
        str = EntropyDecoder.getParameterInfo();
        if (str != null) {
            for (i = str.length - 1; i >= 0; i--) {
                vec.addElement(str[i]);
            }
        }
        str = ROIDeScaler.getParameterInfo();
        if (str != null) {
            for (i = str.length - 1; i >= 0; i--) {
                vec.addElement(str[i]);
            }
        }
        str = Dequantizer.getParameterInfo();
        if (str != null) {
            for (i = str.length - 1; i >= 0; i--) {
                vec.addElement(str[i]);
            }
        }
        str = InvCompTransf.getParameterInfo();
        if (str != null) {
            for (i = str.length - 1; i >= 0; i--) {
                vec.addElement(str[i]);
            }
        }
        str = HeaderDecoder.getParameterInfo();
        if (str != null) {
            for (i = str.length - 1; i >= 0; i--) {
                vec.addElement(str[i]);
            }
        }
        str = ColorSpaceMapper.getParameterInfo();
        if (str != null) {
            for (i = str.length - 1; i >= 0; i--) {
                vec.addElement(str[i]);
            }
        }
        str = getParameterInfo();
        if (str != null) {
            for (i = str.length - 1; i >= 0; i--) {
                vec.addElement(str[i]);
            }
        }
        str = (String[][]) Array.newInstance(String.class, new int[]{vec.size(), 4});
        if (str != null) {
            for (i = str.length - 1; i >= 0; i--) {
                str[i] = (String[]) vec.elementAt(i);
            }
        }
        return str;
    }

    private void warning(String msg) {
        System.out.println(msg);
    }

    private void printVersionAndCopyright() {
        System.out.println("JJ2000's JPEG 2000 Grib2JpegDecoder\n");
    }

    private void printUsage() {
        System.out.println("Usage:");
        System.out.println("Grib2JpegDecoder args...\n");
        System.out.println("The exit code of the decoder is non-zero if an error occurs.");
        System.out.println("The following arguments are recongnized:\n");
        printParamInfo(getAllParameters());
    }

    private void printParamInfo(String[][] pinfo) {
        for (int i = 0; i < pinfo.length; i++) {
            String defval = this.defpl.getParameter(pinfo[i][0]);
            if (defval != null) {
                System.out.println("-" + pinfo[i][0] + (pinfo[i][1] != null ? " " + pinfo[i][1] + " " : " ") + "(default = " + defval + ")");
            } else {
                System.out.println("-" + pinfo[i][0] + (pinfo[i][1] != null ? " " + pinfo[i][1] : ""));
            }
            if (pinfo[i][2] != null) {
                System.out.println(pinfo[i][2]);
            }
        }
    }

    public void exit() {
        if (!this.isChildProcess) {
            System.exit(0);
        }
    }

    public void setChildProcess(boolean b) {
        this.isChildProcess = b;
    }
}
