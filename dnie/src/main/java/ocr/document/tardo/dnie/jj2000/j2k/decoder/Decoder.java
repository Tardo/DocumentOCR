package jj2000.j2k.decoder;

import colorspace.ColorSpace;
import colorspace.ColorSpaceMapper;
import java.awt.Frame;
import java.lang.reflect.Array;
import java.util.Enumeration;
import java.util.Vector;
import jj2000.disp.ImgScrollPane;
import jj2000.disp.TitleUpdater;
import jj2000.j2k.codestream.HeaderInfo;
import jj2000.j2k.codestream.reader.BitstreamReaderAgent;
import jj2000.j2k.codestream.reader.HeaderDecoder;
import jj2000.j2k.entropy.decoder.EntropyDecoder;
import jj2000.j2k.image.invcomptransf.InvCompTransf;
import jj2000.j2k.quantization.dequantizer.Dequantizer;
import jj2000.j2k.roi.ROIDeScaler;
import jj2000.j2k.util.FacilityManager;
import jj2000.j2k.util.MsgLogger;
import jj2000.j2k.util.ParameterList;

public class Decoder implements Runnable {
    private static final String[][] pinfo;
    private static final char[] vprfxs = new char[]{BitstreamReaderAgent.OPT_PREFIX, EntropyDecoder.OPT_PREFIX, 'R', Dequantizer.OPT_PREFIX, InvCompTransf.OPT_PREFIX, HeaderDecoder.OPT_PREFIX, 'I'};
    private ColorSpace csMap;
    private ParameterList defpl;
    private int exitCode;
    private HeaderInfo hi;
    private boolean isChildProcess;
    private ImgScrollPane isp;
    private ParameterList pl;
    TitleUpdater title;
    private Frame win;

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

    public Decoder(ParameterList pl, ImgScrollPane isp) {
        this.csMap = null;
        this.title = null;
        this.isChildProcess = false;
        this.win = null;
        this.pl = pl;
        this.defpl = pl.getDefaultParameterList();
        this.isp = isp;
    }

    public Decoder(ParameterList pl) {
        this(pl, null);
    }

    public int getExitCode() {
        return this.exitCode;
    }

    public static String[][] getParameterInfo() {
        return pinfo;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void run() {
        /*
        r63 = this;
        r50 = "";
        r48 = "";
        r49 = "";
        r47 = 0;
        r35 = 0;
        r7 = 0;
        r25 = 0;
        r33 = 0;
        r38 = 0;
        r16 = "";
        r0 = r63;
        r6 = r0.pl;	 Catch:{ StringFormatException -> 0x008b, NumberFormatException -> 0x012d }
        r8 = "v";
        r6 = r6.getBooleanParameter(r8);	 Catch:{ StringFormatException -> 0x008b, NumberFormatException -> 0x012d }
        if (r6 == 0) goto L_0x0022;
    L_0x001f:
        r63.printVersionAndCopyright();	 Catch:{ StringFormatException -> 0x008b, NumberFormatException -> 0x012d }
    L_0x0022:
        r0 = r63;
        r6 = r0.pl;	 Catch:{ StringFormatException -> 0x008b, NumberFormatException -> 0x012d }
        r8 = "u";
        r6 = r6.getParameter(r8);	 Catch:{ StringFormatException -> 0x008b, NumberFormatException -> 0x012d }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ StringFormatException -> 0x008b, NumberFormatException -> 0x012d }
        if (r6 == 0) goto L_0x0038;
    L_0x0034:
        r63.printUsage();	 Catch:{ StringFormatException -> 0x008b, NumberFormatException -> 0x012d }
    L_0x0037:
        return;
    L_0x0038:
        r0 = r63;
        r6 = r0.pl;	 Catch:{ StringFormatException -> 0x008b, NumberFormatException -> 0x012d }
        r8 = "verbose";
        r60 = r6.getBooleanParameter(r8);	 Catch:{ StringFormatException -> 0x008b, NumberFormatException -> 0x012d }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x018c, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = vprfxs;	 Catch:{ IllegalArgumentException -> 0x018c, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r9 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x018c, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = pinfo;	 Catch:{ IllegalArgumentException -> 0x018c, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = jj2000.j2k.util.ParameterList.toNameArray(r9);	 Catch:{ IllegalArgumentException -> 0x018c, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.checkList(r8, r9);	 Catch:{ IllegalArgumentException -> 0x018c, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "i";
        r36 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r36 != 0) goto L_0x01b8;
    L_0x0061:
        r6 = "Input file ('-i' option) has not been specified";
        r8 = 1;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x006a:
        r26 = move-exception;
        r6 = r26.getMessage();
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);
        r0 = r63;
        r6 = r0.pl;
        r8 = "debug";
        r6 = r6.getParameter(r8);
        r8 = "on";
        r6 = r6.equals(r8);
        if (r6 == 0) goto L_0x0037;
    L_0x0087:
        r26.printStackTrace();
        goto L_0x0037;
    L_0x008b:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "An error occured while parsing the arguments:\n";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x00e8;
    L_0x00bb:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x00c0:
        r26 = move-exception;
        r6 = r26.getMessage();
        if (r6 == 0) goto L_0x113f;
    L_0x00c7:
        r6 = r26.getMessage();
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);
    L_0x00d1:
        r0 = r63;
        r6 = r0.pl;
        r8 = "debug";
        r6 = r6.getParameter(r8);
        r8 = "on";
        r6 = r6.equals(r8);
        if (r6 == 0) goto L_0x1149;
    L_0x00e3:
        r26.printStackTrace();
        goto L_0x0037;
    L_0x00e8:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x00f2:
        r26 = move-exception;
        r6 = r26.getMessage();
        if (r6 == 0) goto L_0x1153;
    L_0x00f9:
        r6 = new java.lang.StringBuilder;
        r6.<init>();
        r8 = "An uncaught runtime exception has occurred:\n";
        r6 = r6.append(r8);
        r8 = r26.getMessage();
        r6 = r6.append(r8);
        r6 = r6.toString();
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);
    L_0x0116:
        r0 = r63;
        r6 = r0.pl;
        r8 = "debug";
        r6 = r6.getParameter(r8);
        r8 = "on";
        r6 = r6.equals(r8);
        if (r6 == 0) goto L_0x115d;
    L_0x0128:
        r26.printStackTrace();
        goto L_0x0037;
    L_0x012d:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "An error occured while parsing the arguments:\n";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0182;
    L_0x015d:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0162:
        r26 = move-exception;
        r6 = "An uncaught exception has occurred.";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);
        r0 = r63;
        r6 = r0.pl;
        r8 = "debug";
        r6 = r6.getParameter(r8);
        r8 = "on";
        r6 = r6.equals(r8);
        if (r6 == 0) goto L_0x1167;
    L_0x017d:
        r26.printStackTrace();
        goto L_0x0037;
    L_0x0182:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x018c:
        r26 = move-exception;
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x01ae;
    L_0x01a9:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x01ae:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x01b8:
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "o";
        r50 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r50 != 0) goto L_0x02d2;
    L_0x01c4:
        r25 = 1;
    L_0x01c6:
        r6 = "/";
        r0 = r36;
        r6 = r0.indexOf(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1;
        if (r6 < r8) goto L_0x0451;
    L_0x01d1:
        r6 = "/";
        r0 = r36;
        r6 = r0.indexOf(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6 + -1;
        r0 = r36;
        r6 = r0.charAt(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 58;
        if (r6 != r8) goto L_0x0451;
    L_0x01e5:
        r39 = new java.net.URL;	 Catch:{ MalformedURLException -> 0x0306 }
        r0 = r39;
        r1 = r36;
        r0.<init>(r1);	 Catch:{ MalformedURLException -> 0x0306 }
        r20 = r39.openConnection();	 Catch:{ IOException -> 0x0343 }
        r20.connect();	 Catch:{ IOException -> 0x0343 }
        r22 = r20.getContentLength();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r41 = r20.getInputStream();	 Catch:{ IOException -> 0x03a4 }
        r6 = -1;
        r0 = r22;
        if (r0 == r6) goto L_0x0405;
    L_0x0202:
        r4 = new jj2000.j2k.util.ISRandomAccessIO;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = 1;
        r0 = r41;
        r1 = r22;
        r2 = r22;
        r4.<init>(r0, r1, r6, r2);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x020e:
        r4.read();	 Catch:{ IOException -> 0x040e }
        r6 = 0;
        r4.seek(r6);	 Catch:{ IOException -> 0x040e }
    L_0x0215:
        r28 = new jj2000.j2k.fileformat.reader.FileFormatReader;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r28;
        r0.<init>(r4);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r28.readFileFormat();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r28;
        r6 = r0.JP2FFUsed;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x022c;
    L_0x0225:
        r6 = r28.getFirstCodeStreamPos();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r4.seek(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x022c:
        r6 = new jj2000.j2k.codestream.HeaderInfo;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r0.hi = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r5 = new jj2000.j2k.codestream.reader.HeaderDecoder;	 Catch:{ EOFException -> 0x04b7 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ EOFException -> 0x04b7 }
        r0 = r63;
        r8 = r0.hi;	 Catch:{ EOFException -> 0x04b7 }
        r5.<init>(r4, r6, r8);	 Catch:{ EOFException -> 0x04b7 }
        r43 = r5.getNumComps();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.siz;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r45 = r6.getNumTiles();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r7 = r5.getDecoderSpecs();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r60 == 0) goto L_0x0523;
    L_0x0256:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r43;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = " component(s) in codestream, ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r45;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = " tile(s)\n";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r37 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r37;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Image dimension: ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r37 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r17 = 0;
    L_0x028e:
        r0 = r17;
        r1 = r43;
        if (r0 >= r1) goto L_0x04e1;
    L_0x0294:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r37;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.siz;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r17;
        r8 = r8.getCompImgWidth(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "x";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.siz;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r17;
        r8 = r8.getCompImgHeight(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = " ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r37 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r17 = r17 + 1;
        goto L_0x028e;
    L_0x02d2:
        r6 = 46;
        r0 = r50;
        r6 = r0.lastIndexOf(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = -1;
        if (r6 == r8) goto L_0x0300;
    L_0x02dd:
        r6 = 46;
        r0 = r50;
        r6 = r0.lastIndexOf(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r50.length();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r50;
        r49 = r0.substring(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = 0;
        r8 = 46;
        r0 = r50;
        r8 = r0.lastIndexOf(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r50;
        r48 = r0.substring(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x01c6;
    L_0x0300:
        r48 = r50;
        r49 = ".pgx";
        goto L_0x01c6;
    L_0x0306:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Malformed URL for input file ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r36;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 4;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0339;
    L_0x0334:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0339:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0343:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot open connection to ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r36;
        r8 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0397;
    L_0x035b:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0372:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 4;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x039a;
    L_0x0392:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0397:
        r6 = "";
        goto L_0x0372;
    L_0x039a:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x03a4:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot get data from connection to ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r36;
        r8 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x03f8;
    L_0x03bc:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x03d3:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 4;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x03fb;
    L_0x03f3:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x03f8:
        r6 = "";
        goto L_0x03d3;
    L_0x03fb:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0405:
        r4 = new jj2000.j2k.util.ISRandomAccessIO;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r41;
        r4.<init>(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x020e;
    L_0x040e:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot get input data from ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r36;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = " Invalid URL?";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 4;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0447;
    L_0x0442:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0447:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0451:
        r4 = new jj2000.j2k.io.BEBufferedRandomAccessFile;	 Catch:{ IOException -> 0x045c }
        r6 = "r";
        r0 = r36;
        r4.<init>(r0, r6);	 Catch:{ IOException -> 0x045c }
        goto L_0x0215;
    L_0x045c:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot open input file ";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x04aa;
    L_0x046e:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0485:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 4;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x04ad;
    L_0x04a5:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x04aa:
        r6 = "";
        goto L_0x0485;
    L_0x04ad:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x04b7:
        r26 = move-exception;
        r6 = "Codestream too short or bad header, unable to decode.";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x04d7;
    L_0x04d2:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x04d7:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x04e1:
        r6 = 1;
        r0 = r45;
        if (r0 == r6) goto L_0x0519;
    L_0x04e6:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r37;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "\nNom. Tile dim. (in canvas): ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.siz;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.xtsiz;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "x";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.siz;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.ytsiz;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r37 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0519:
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1;
        r0 = r37;
        r6.printmsg(r8, r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0523:
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "cdstr_info";
        r6 = r6.getBooleanParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0552;
    L_0x052f:
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1;
        r9 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r11 = "Main header:\n";
        r9 = r9.append(r11);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r11 = r0.hi;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r11 = r11.toStringMainHeader();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r9.append(r11);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r9.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.printmsg(r8, r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0552:
        r0 = r43;
        r0 = new int[r0];	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r23 = r0;
        r30 = 0;
    L_0x055a:
        r0 = r30;
        r1 = r43;
        if (r0 >= r1) goto L_0x056b;
    L_0x0560:
        r0 = r30;
        r6 = r5.getOriginalBitDepth(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r23[r30] = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r30 = r30 + 1;
        goto L_0x055a;
    L_0x056b:
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IOException -> 0x0962, IllegalArgumentException -> 0x09bd, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8 = r0.pl;	 Catch:{ IOException -> 0x0962, IllegalArgumentException -> 0x09bd, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = "cdstr_info";
        r8 = r8.getBooleanParameter(r9);	 Catch:{ IOException -> 0x0962, IllegalArgumentException -> 0x09bd, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r9 = r0.hi;	 Catch:{ IOException -> 0x0962, IllegalArgumentException -> 0x09bd, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r15 = jj2000.j2k.codestream.reader.BitstreamReaderAgent.createInstance(r4, r5, r6, r7, r8, r9);	 Catch:{ IOException -> 0x0962, IllegalArgumentException -> 0x09bd, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0a18, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r27 = r5.createEntropyDecoder(r15, r6);	 Catch:{ IllegalArgumentException -> 0x0a18, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0a73, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r27;
        r54 = r5.createROIDeScaler(r0, r6, r7);	 Catch:{ IllegalArgumentException -> 0x0a73, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r54;
        r1 = r23;
        r24 = r5.createDequantizer(r0, r1, r7);	 Catch:{ IllegalArgumentException -> 0x0ace, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r24;
        r40 = jj2000.j2k.wavelet.synthesis.InverseWT.createInstance(r0, r7);	 Catch:{ IllegalArgumentException -> 0x0b29, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r52 = r15.getImgRes();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r40;
        r1 = r52;
        r0.setImgResLevel(r1);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r21 = new jj2000.j2k.image.ImgDataConverter;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = 0;
        r0 = r21;
        r1 = r40;
        r0.<init>(r1, r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r31 = new jj2000.j2k.image.invcomptransf.InvCompTransf;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r31;
        r1 = r21;
        r2 = r23;
        r0.<init>(r1, r7, r2, r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r28;
        r6 = r0.JP2FFUsed;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0c00;
    L_0x05cb:
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "nocolorspace";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "off";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0c00;
    L_0x05dd:
        r6 = new colorspace.ColorSpace;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>(r4, r5, r8);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r0.csMap = r6;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r31;
        r18 = r5.createChannelDefinitionMapper(r0, r6);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r18;
        r53 = r5.createResampler(r0, r6);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r53;
        r51 = r5.createPalettizedColorSpaceMapper(r0, r6);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r51;
        r19 = r5.createColorSpaceMapper(r0, r6);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.debugging();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x06af;
    L_0x061c:
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        r9 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9.<init>();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r11 = "";
        r9 = r9.append(r11);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r11 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r9.append(r11);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r9.toString();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.printmsg(r8, r9);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        r9 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9.<init>();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r11 = "";
        r9 = r9.append(r11);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r18;
        r9 = r9.append(r0);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r9.toString();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.printmsg(r8, r9);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        r9 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9.<init>();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r11 = "";
        r9 = r9.append(r11);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r53;
        r9 = r9.append(r0);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r9.toString();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.printmsg(r8, r9);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        r9 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9.<init>();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r11 = "";
        r9 = r9.append(r11);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r51;
        r9 = r9.append(r0);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r9.toString();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.printmsg(r8, r9);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        r9 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9.<init>();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r11 = "";
        r9 = r9.append(r11);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r19;
        r9 = r9.append(r0);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r9.toString();	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.printmsg(r8, r9);	 Catch:{ IllegalArgumentException -> 0x0b84, ColorSpaceException -> 0x0bc2, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x06af:
        r10 = r19;
        if (r19 != 0) goto L_0x06b5;
    L_0x06b3:
        r10 = r31;
    L_0x06b5:
        r44 = r10.getNumComps();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r25 == 0) goto L_0x0c12;
    L_0x06bb:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "JJ2000: ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = new java.io.File;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r36;
        r8.<init>(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.getName();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = " ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r10.getImgWidth();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "x";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r10.getImgHeight();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r16 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0c04;
    L_0x06fb:
        r6 = new java.awt.Frame;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r16;
        r8 = r8.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = " @ (0,0) : 1";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r0.win = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = java.awt.Color.white;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.setBackground(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = new jj2000.disp.ExitHandler;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8.<init>(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.addWindowListener(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = new jj2000.disp.ImgScrollPane;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 0;
        r6.<init>(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r0.isp = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = "Center";
        r6.add(r8, r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = new jj2000.disp.ImgKeyListener;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r9 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8.<init>(r9, r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.addKeyListener(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = new jj2000.disp.ImgKeyListener;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r9 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8.<init>(r9, r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.addKeyListener(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x076b:
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0c0b;
    L_0x0771:
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.addNotify();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r38 = r6.getInsets();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = 0;
        r57 = r10.getCompSubsX(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = 0;
        r58 = r10.getCompSubsY(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r10.getImgWidth();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6 + r57;
        r6 = r6 + -1;
        r61 = r6 / r57;
        r6 = r10.getImgHeight();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6 + r58;
        r6 = r6 + -1;
        r29 = r6 / r58;
        r62 = new java.awt.Dimension;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r38;
        r6 = r0.left;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6 + r61;
        r0 = r38;
        r8 = r0.right;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6 + r8;
        r0 = r38;
        r8 = r0.top;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8 + r29;
        r0 = r38;
        r9 = r0.bottom;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8 + r9;
        r0 = r62;
        r0.<init>(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.getToolkit();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r55 = r6.getScreenSize();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r62;
        r6 = r0.width;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = (float) r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r55;
        r8 = r0.width;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8 * 8;
        r8 = (float) r8;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = 1092616192; // 0x41200000 float:10.0 double:5.398241246E-315;
        r8 = r8 / r9;
        r6 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1));
        if (r6 <= 0) goto L_0x07e9;
    L_0x07da:
        r0 = r55;
        r6 = r0.width;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6 * 8;
        r6 = (float) r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1092616192; // 0x41200000 float:10.0 double:5.398241246E-315;
        r6 = r6 / r8;
        r6 = (int) r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r62;
        r0.width = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x07e9:
        r0 = r62;
        r6 = r0.height;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = (float) r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r55;
        r8 = r0.height;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8 * 8;
        r8 = (float) r8;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = 1092616192; // 0x41200000 float:10.0 double:5.398241246E-315;
        r8 = r8 / r9;
        r6 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1));
        if (r6 <= 0) goto L_0x080b;
    L_0x07fc:
        r0 = r55;
        r6 = r0.height;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6 * 8;
        r6 = (float) r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1092616192; // 0x41200000 float:10.0 double:5.398241246E-315;
        r6 = r6 / r8;
        r6 = (int) r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r62;
        r0.height = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x080b:
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r62;
        r6.setSize(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.validate();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1;
        r6.setVisible(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = new jj2000.disp.TitleUpdater;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r8 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r9 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r16;
        r6.<init>(r8, r9, r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r0.title = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r59 = new java.lang.Thread;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.title;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r59;
        r0.<init>(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r59.start();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0844:
        r6 = r7.dls;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r42 = r6.getMin();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r60 == 0) goto L_0x08ea;
    L_0x084c:
        r0 = r42;
        r1 = r52;
        if (r0 == r1) goto L_0x08a4;
    L_0x0852:
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = "Reconstructing resolution ";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r52;
        r8 = r8.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = " on ";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r42;
        r8 = r8.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = " (";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r52;
        r9 = r15.getImgWidth(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = "x";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r52;
        r9 = r15.getImgHeight(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ")";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = 8;
        r11 = 8;
        r6.println(r8, r9, r11);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x08a4:
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "rate";
        r6 = r6.getFloatParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = -1082130432; // 0xffffffffbf800000 float:-1.0 double:NaN;
        r6 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1));
        if (r6 == 0) goto L_0x08ea;
    L_0x08b4:
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = "Target rate = ";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r15.getTargetRate();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = " bpp (";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r15.getTargetNbytes();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = " bytes)";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = 8;
        r11 = 8;
        r6.println(r8, r9, r11);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x08ea:
        if (r25 == 0) goto L_0x0f40;
    L_0x08ec:
        r6 = java.lang.Thread.currentThread();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r6.setPriority(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r33 = jj2000.disp.BlkImgDataSrcImageProducer.createImage(r10, r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        r8 = java.awt.Cursor.getPredefinedCursor(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.setCursor(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x091a;
    L_0x090e:
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        r8 = java.awt.Cursor.getPredefinedCursor(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.setCursor(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x091a:
        r0 = r63;
        r6 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r33;
        r6.setImage(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 0;
        r8 = java.awt.Cursor.getPredefinedCursor(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.setCursor(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0941;
    L_0x0935:
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 0;
        r8 = java.awt.Cursor.getPredefinedCursor(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.setCursor(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0941:
        r0 = r63;
        r6 = r0.win;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0e9f;
    L_0x0947:
        r0 = r63;
        r6 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 0;
        r0 = r33;
        r56 = r6.checkImage(r0, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r56 & 64;
        if (r6 == 0) goto L_0x0e89;
    L_0x0956:
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        r9 = "An unknown error occurred while producing the image";
        r6.printmsg(r8, r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0962:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Error while reading bit stream header or parsing packets";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x09b0;
    L_0x0974:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x098b:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 4;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x09b3;
    L_0x09ab:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x09b0:
        r6 = "";
        goto L_0x098b;
    L_0x09b3:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x09bd:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot instantiate bit stream reader";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0a0b;
    L_0x09cf:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x09e6:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0a0e;
    L_0x0a06:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0a0b:
        r6 = "";
        goto L_0x09e6;
    L_0x0a0e:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0a18:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot instantiate entropy decoder";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0a66;
    L_0x0a2a:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0a41:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0a69;
    L_0x0a61:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0a66:
        r6 = "";
        goto L_0x0a41;
    L_0x0a69:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0a73:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot instantiate roi de-scaler.";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0ac1;
    L_0x0a85:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0a9c:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0ac4;
    L_0x0abc:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0ac1:
        r6 = "";
        goto L_0x0a9c;
    L_0x0ac4:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0ace:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot instantiate dequantizer";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0b1c;
    L_0x0ae0:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0af7:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0b1f;
    L_0x0b17:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0b1c:
        r6 = "";
        goto L_0x0af7;
    L_0x0b1f:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0b29:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot instantiate inverse wavelet transform";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0b77;
    L_0x0b3b:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0b52:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0b7a;
    L_0x0b72:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0b77:
        r6 = "";
        goto L_0x0b52;
    L_0x0b7a:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0b84:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Could not instantiate ICC profiler";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0bbf;
    L_0x0b96:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0bad:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1;
        r0 = r63;
        r1 = r26;
        r0.error(r6, r8, r1);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0bbf:
        r6 = "";
        goto L_0x0bad;
    L_0x0bc2:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "error processing jp2 colorspace information";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0bfd;
    L_0x0bd4:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ": ";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0beb:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1;
        r0 = r63;
        r1 = r26;
        r0.error(r6, r8, r1);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0bfd:
        r6 = "    ";
        goto L_0x0beb;
    L_0x0c00:
        r19 = r31;
        goto L_0x06af;
    L_0x0c04:
        r6 = 0;
        r0 = r63;
        r0.win = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x076b;
    L_0x0c0b:
        r6 = 0;
        r0 = r63;
        r0.title = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0844;
    L_0x0c12:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0c6d;
    L_0x0c18:
        r6 = ".PPM";
        r0 = r49;
        r6 = r0.equalsIgnoreCase(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0cb6;
    L_0x0c22:
        r6 = 3;
        r0 = r44;
        if (r0 != r6) goto L_0x0c63;
    L_0x0c27:
        r6 = 0;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0c63;
    L_0x0c30:
        r6 = 1;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0c63;
    L_0x0c39:
        r6 = 2;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0c63;
    L_0x0c42:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 0;
        r6 = r6.isOutputSigned(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0c63;
    L_0x0c4d:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1;
        r6 = r6.isOutputSigned(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0c63;
    L_0x0c58:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r6 = r6.isOutputSigned(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0cb6;
    L_0x0c63:
        r6 = "Specified PPM output file but compressed image is not of the correct format for PPM or limited decoded components to less than 3.";
        r8 = 1;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0c6d:
        r6 = ".PPM";
        r0 = r49;
        r6 = r0.equalsIgnoreCase(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0cb6;
    L_0x0c77:
        r6 = 3;
        r0 = r44;
        if (r0 != r6) goto L_0x0cac;
    L_0x0c7c:
        r6 = 0;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0cac;
    L_0x0c85:
        r6 = 1;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0cac;
    L_0x0c8e:
        r6 = 2;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0cac;
    L_0x0c97:
        r6 = 0;
        r6 = r5.isOriginalSigned(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0cac;
    L_0x0c9e:
        r6 = 1;
        r6 = r5.isOriginalSigned(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0cac;
    L_0x0ca5:
        r6 = 2;
        r6 = r5.isOriginalSigned(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0cb6;
    L_0x0cac:
        r6 = "Specified PPM output file but compressed image is not of the correct format for PPM or limited decoded components to less than 3.";
        r8 = 1;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0cb6:
        r0 = r44;
        r0 = new java.lang.String[r0];	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r47 = r0;
        r30 = 0;
    L_0x0cbe:
        r0 = r30;
        r1 = r44;
        if (r0 >= r1) goto L_0x0ccb;
    L_0x0cc4:
        r6 = "";
        r47[r30] = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r30 = r30 + 1;
        goto L_0x0cbe;
    L_0x0ccb:
        r6 = 1;
        r0 = r44;
        if (r0 <= r6) goto L_0x0d4b;
    L_0x0cd0:
        r6 = ".PPM";
        r0 = r49;
        r6 = r0.equalsIgnoreCase(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0d4b;
    L_0x0cda:
        r6 = ".PGM";
        r0 = r49;
        r6 = r0.equalsIgnoreCase(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0d1d;
    L_0x0ce4:
        r30 = 0;
    L_0x0ce6:
        r0 = r30;
        r1 = r44;
        if (r0 >= r1) goto L_0x0d1d;
    L_0x0cec:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0d08;
    L_0x0cf2:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r30;
        r6 = r6.isOutputSigned(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0d1a;
    L_0x0cfe:
        r6 = "Specified PGM output file but compressed image is not of the correct format for PGM.";
        r8 = 1;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0d08:
        r0 = r30;
        r6 = r5.isOriginalSigned(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0d1a;
    L_0x0d10:
        r6 = "Specified PGM output file but compressed image is not of the correct format for PGM.";
        r8 = 1;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0d1a:
        r30 = r30 + 1;
        goto L_0x0ce6;
    L_0x0d1d:
        r30 = 0;
    L_0x0d1f:
        r0 = r30;
        r1 = r44;
        if (r0 >= r1) goto L_0x0d63;
    L_0x0d25:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r48;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "-";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r30 + 1;
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r49;
        r6 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r47[r30] = r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r30 = r30 + 1;
        goto L_0x0d1f;
    L_0x0d4b:
        r6 = 0;
        r8 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r48;
        r8 = r8.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r49;
        r8 = r8.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r47[r6] = r8;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0d63:
        r6 = ".PPM";
        r0 = r49;
        r6 = r0.equalsIgnoreCase(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0e3a;
    L_0x0d6d:
        r6 = 1;
        r0 = new jj2000.j2k.image.output.ImgWriter[r6];	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r35 = r0;
        r6 = 0;
        r8 = new jj2000.j2k.image.output.ImgWriterPPM;	 Catch:{ IOException -> 0x0dd9 }
        r9 = 0;
        r9 = r47[r9];	 Catch:{ IOException -> 0x0dd9 }
        r11 = 0;
        r12 = 1;
        r13 = 2;
        r8.<init>(r9, r10, r11, r12, r13);	 Catch:{ IOException -> 0x0dd9 }
        r35[r6] = r8;	 Catch:{ IOException -> 0x0dd9 }
    L_0x0d80:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0e42;
    L_0x0d86:
        r0 = r35;
        r6 = r0.length;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        if (r6 != r8) goto L_0x0844;
    L_0x0d8c:
        r6 = 0;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0844;
    L_0x0d95:
        r6 = 1;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0844;
    L_0x0d9e:
        r6 = 2;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0844;
    L_0x0da7:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 0;
        r6 = r6.isOutputSigned(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0844;
    L_0x0db2:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1;
        r6 = r6.isOutputSigned(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0844;
    L_0x0dbd:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r6 = r6.isOutputSigned(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0844;
    L_0x0dc8:
        r6 = r7.cts;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.isCompTransfUsed();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0844;
    L_0x0dd0:
        r6 = "JJ2000 is quicker with one PPM output file than with 3 PGM/PGX output files when a component transformation is applied.";
        r0 = r63;
        r0.warning(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0844;
    L_0x0dd9:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot write PPM header or open output file";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r30;
        r8 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0e2d;
    L_0x0df1:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0e08:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0e30;
    L_0x0e28:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0e2d:
        r6 = "";
        goto L_0x0e08;
    L_0x0e30:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0e3a:
        r0 = r44;
        r0 = new jj2000.j2k.image.output.ImgWriter[r0];	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r35 = r0;
        goto L_0x0d80;
    L_0x0e42:
        r0 = r35;
        r6 = r0.length;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        if (r6 != r8) goto L_0x0844;
    L_0x0e48:
        r6 = 0;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0844;
    L_0x0e51:
        r6 = 1;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0844;
    L_0x0e5a:
        r6 = 2;
        r6 = r10.getNomRangeBits(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 8;
        if (r6 > r8) goto L_0x0844;
    L_0x0e63:
        r6 = 0;
        r6 = r5.isOriginalSigned(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0844;
    L_0x0e6a:
        r6 = 1;
        r6 = r5.isOriginalSigned(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0844;
    L_0x0e71:
        r6 = 2;
        r6 = r5.isOriginalSigned(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 != 0) goto L_0x0844;
    L_0x0e78:
        r6 = r7.cts;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.isCompTransfUsed();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0844;
    L_0x0e80:
        r6 = "JJ2000 is quicker with one PPM output file than with 3 PGM/PGX output files when a component transformation is applied.";
        r0 = r63;
        r0.warning(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0844;
    L_0x0e89:
        r0 = r56;
        r6 = r0 & 128;
        if (r6 == 0) goto L_0x0f10;
    L_0x0e8f:
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 3;
        r9 = "Image production was aborted for some unknown reason";
        r6.printmsg(r8, r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0e99:
        r0 = r56;
        r6 = r0 & 224;
        if (r6 == 0) goto L_0x0947;
    L_0x0e9f:
        if (r60 == 0) goto L_0x0037;
    L_0x0ea1:
        r14 = r15.getActualRate();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r46 = r15.getActualNbytes();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r28;
        r6 = r0.JP2FFUsed;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0eca;
    L_0x0eaf:
        r6 = 1090519040; // 0x41000000 float:8.0 double:5.38787994E-315;
        r0 = r46;
        r8 = (float) r0;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6 * r8;
        r6 = r6 / r14;
        r0 = (int) r6;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r32 = r0;
        r6 = r28.getFirstCodeStreamPos();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r46 = r46 + r6;
        r0 = r46;
        r6 = (float) r0;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 1090519040; // 0x41000000 float:8.0 double:5.38787994E-315;
        r6 = r6 * r8;
        r0 = r32;
        r8 = (float) r0;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r14 = r6 / r8;
    L_0x0eca:
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "ncb_quit";
        r6 = r6.getIntParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = -1;
        if (r6 != r8) goto L_0x111d;
    L_0x0ed7:
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = "Actual bitrate = ";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.append(r14);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = " bpp (i.e. ";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r46;
        r8 = r8.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = " bytes)";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = 8;
        r11 = 8;
        r6.println(r8, r9, r11);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0f07:
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.flush();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0f10:
        r6 = r56 & 32;
        if (r6 == 0) goto L_0x0f33;
    L_0x0f14:
        r34 = new jj2000.disp.ImgMouseListener;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r34;
        r0.<init>(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r34;
        r6.addMouseListener(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.isp;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r34;
        r6.addMouseMotionListener(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0e99;
    L_0x0f33:
        java.lang.Thread.currentThread();	 Catch:{ InterruptedException -> 0x0f3d }
        r8 = 100;
        java.lang.Thread.sleep(r8);	 Catch:{ InterruptedException -> 0x0f3d }
        goto L_0x0e99;
    L_0x0f3d:
        r6 = move-exception;
        goto L_0x0e99;
    L_0x0f40:
        r30 = 0;
    L_0x0f42:
        r0 = r35;
        r6 = r0.length;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r30;
        if (r0 >= r6) goto L_0x0e9f;
    L_0x0f49:
        r6 = ".PGM";
        r0 = r49;
        r6 = r0.equalsIgnoreCase(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0fcc;
    L_0x0f53:
        r6 = new jj2000.j2k.image.output.ImgWriterPGM;	 Catch:{ IOException -> 0x0f6b }
        r8 = r47[r30];	 Catch:{ IOException -> 0x0f6b }
        r0 = r30;
        r6.<init>(r8, r10, r0);	 Catch:{ IOException -> 0x0f6b }
        r35[r30] = r6;	 Catch:{ IOException -> 0x0f6b }
    L_0x0f5e:
        r6 = r35[r30];	 Catch:{ IOException -> 0x1067 }
        r6.writeAll();	 Catch:{ IOException -> 0x1067 }
        r6 = r35[r30];	 Catch:{ IOException -> 0x10c2 }
        r6.close();	 Catch:{ IOException -> 0x10c2 }
        r30 = r30 + 1;
        goto L_0x0f42;
    L_0x0f6b:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot write PGM header or open output file for component ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r30;
        r8 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0fbf;
    L_0x0f83:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x0f9a:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0fc2;
    L_0x0fba:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0fbf:
        r6 = "";
        goto L_0x0f9a;
    L_0x0fc2:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x0fcc:
        r6 = ".PGX";
        r0 = r49;
        r6 = r0.equalsIgnoreCase(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x0f5e;
    L_0x0fd6:
        r0 = r63;
        r6 = r0.csMap;	 Catch:{ IOException -> 0x0ff3 }
        if (r6 == 0) goto L_0x1047;
    L_0x0fdc:
        r6 = new jj2000.j2k.image.output.ImgWriterPGX;	 Catch:{ IOException -> 0x0ff3 }
        r8 = r47[r30];	 Catch:{ IOException -> 0x0ff3 }
        r0 = r63;
        r9 = r0.csMap;	 Catch:{ IOException -> 0x0ff3 }
        r0 = r30;
        r9 = r9.isOutputSigned(r0);	 Catch:{ IOException -> 0x0ff3 }
        r0 = r30;
        r6.<init>(r8, r10, r0, r9);	 Catch:{ IOException -> 0x0ff3 }
        r35[r30] = r6;	 Catch:{ IOException -> 0x0ff3 }
        goto L_0x0f5e;
    L_0x0ff3:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "Cannot write PGX header or open output file for component ";
        r6 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r30;
        r8 = r6.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x105a;
    L_0x100b:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x1022:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x105d;
    L_0x1042:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x1047:
        r6 = new jj2000.j2k.image.output.ImgWriterPGX;	 Catch:{ IOException -> 0x0ff3 }
        r8 = r47[r30];	 Catch:{ IOException -> 0x0ff3 }
        r0 = r30;
        r9 = r5.isOriginalSigned(r0);	 Catch:{ IOException -> 0x0ff3 }
        r0 = r30;
        r6.<init>(r8, r10, r0, r9);	 Catch:{ IOException -> 0x0ff3 }
        r35[r30] = r6;	 Catch:{ IOException -> 0x0ff3 }
        goto L_0x0f5e;
    L_0x105a:
        r6 = "";
        goto L_0x1022;
    L_0x105d:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x1067:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "I/O error while writing output file";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x10b5;
    L_0x1079:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x1090:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x10b8;
    L_0x10b0:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x10b5:
        r6 = "";
        goto L_0x1090;
    L_0x10b8:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x10c2:
        r26 = move-exception;
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "I/O error while closing output file (data may be corrupted";
        r8 = r6.append(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x1110;
    L_0x10d4:
        r6 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = ":\n";
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = r26.getMessage();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
    L_0x10eb:
        r6 = r8.append(r6);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r6 = r6.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r63;
        r6 = r0.pl;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "debug";
        r6 = r6.getParameter(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = "on";
        r6 = r6.equals(r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        if (r6 == 0) goto L_0x1113;
    L_0x110b:
        r26.printStackTrace();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x1110:
        r6 = "";
        goto L_0x10eb;
    L_0x1113:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0037;
    L_0x111d:
        r6 = jj2000.j2k.util.FacilityManager.getMsgLogger();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = new java.lang.StringBuilder;	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8.<init>();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = "Number of packet body bytes read = ";
        r8 = r8.append(r9);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r0 = r46;
        r8 = r8.append(r0);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r8 = r8.toString();	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        r9 = 8;
        r11 = 8;
        r6.println(r8, r9, r11);	 Catch:{ IllegalArgumentException -> 0x006a, Error -> 0x00c0, RuntimeException -> 0x00f2, Throwable -> 0x0162 }
        goto L_0x0f07;
    L_0x113f:
        r6 = "An error has occured during decoding.";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);
        goto L_0x00d1;
    L_0x1149:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);
        goto L_0x0037;
    L_0x1153:
        r6 = "An uncaught runtime exception has occurred.";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);
        goto L_0x0116;
    L_0x115d:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);
        goto L_0x0037;
    L_0x1167:
        r6 = "Use '-debug' option for more details";
        r8 = 2;
        r0 = r63;
        r0.error(r6, r8);
        goto L_0x0037;
        */
        throw new UnsupportedOperationException("Method not decompiled: jj2000.j2k.decoder.Decoder.run():void");
    }

    private void error(String msg, int code) {
        this.exitCode = code;
        FacilityManager.getMsgLogger().printmsg(3, msg);
    }

    private void error(String msg, int code, Throwable ex) {
        this.exitCode = code;
        FacilityManager.getMsgLogger().printmsg(3, msg);
        if (this.pl.getParameter("debug").equals("on")) {
            ex.printStackTrace();
        } else {
            error("Use '-debug' option for more details", 2);
        }
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
        FacilityManager.getMsgLogger().printmsg(2, msg);
    }

    private void printVersionAndCopyright() {
        FacilityManager.getMsgLogger().println("JJ2000's JPEG 2000 Decoder\n", 2, 4);
        FacilityManager.getMsgLogger().println("Version: 5.1\n", 2, 4);
        FacilityManager.getMsgLogger().println("Copyright:\n\nThis software module was originally developed by Raphaël Grosbois and Diego Santa Cruz (Swiss Federal Institute of Technology-EPFL); Joel Askelöf (Ericsson Radio Systems AB); and Bertrand Berthelot, David Bouchard, Félix Henry, Gerard Mozelle and Patrice Onno (Canon Research Centre France S.A) in the course of development of the JPEG 2000 standard as specified by ISO/IEC 15444 (JPEG 2000 Standard). This software module is an implementation of a part of the JPEG 2000 Standard. Swiss Federal Institute of Technology-EPFL, Ericsson Radio Systems AB and Canon Research Centre France S.A (collectively JJ2000 Partners) agree not to assert against ISO/IEC and users of the JPEG 2000 Standard (Users) any of their rights under the copyright, not including other intellectual property rights, for this software module with respect to the usage by ISO/IEC and Users of this software module or modifications thereof for use in hardware or software products claiming conformance to the JPEG 2000 Standard. Those intending to use this software module in hardware or software products are advised that their use may infringe existing patents. The original developers of this software module, JJ2000 Partners and ISO/IEC assume no liability for use of this software module or modifications thereof. No license or right to this software module is granted for non JPEG 2000 Standard conforming products. JJ2000 Partners have full right to use this software module for his/her own purpose, assign or donate this software module to any third party and to inhibit third parties from using this software module for non JPEG 2000 Standard conforming products. This copyright notice must be included in all copies or derivative works of this software module.\n\nCopyright (c) 1999/2000 JJ2000 Partners.\n", 2, 4);
        FacilityManager.getMsgLogger().println("Send bug reports to: jj2000-bugs@ltssg3.epfl.ch\n", 2, 4);
    }

    private void printUsage() {
        MsgLogger ml = FacilityManager.getMsgLogger();
        ml.println("Usage:", 0, 0);
        ml.println("JJ2KDecoder args...\n", 10, 12);
        ml.println("The exit code of the decoder is non-zero if an error occurs.", 2, 4);
        ml.println("The following arguments are recongnized:\n", 2, 4);
        printParamInfo(ml, getAllParameters());
        FacilityManager.getMsgLogger().println("\n\n", 0, 0);
        FacilityManager.getMsgLogger().println("Send bug reports to: jj2000-bugs@ltssg3.epfl.ch\n", 2, 4);
    }

    private void printParamInfo(MsgLogger out, String[][] pinfo) {
        for (int i = 0; i < pinfo.length; i++) {
            String defval = this.defpl.getParameter(pinfo[i][0]);
            if (defval != null) {
                out.println("-" + pinfo[i][0] + (pinfo[i][1] != null ? " " + pinfo[i][1] + " " : " ") + "(default = " + defval + ")", 4, 8);
            } else {
                out.println("-" + pinfo[i][0] + (pinfo[i][1] != null ? " " + pinfo[i][1] : ""), 4, 8);
            }
            if (pinfo[i][2] != null) {
                out.println(pinfo[i][2], 6, 6);
            }
        }
    }

    public void exit() {
        if (this.isChildProcess) {
            if (this.win != null) {
                this.win.dispose();
            }
            if (this.title != null) {
                this.title.done = true;
                return;
            }
            return;
        }
        System.exit(0);
    }

    public void setChildProcess(boolean b) {
        this.isChildProcess = b;
    }
}
