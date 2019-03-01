package jj2000.j2k.decoder;

import jj2000.j2k.util.FacilityManager;
import jj2000.j2k.util.ParameterList;

public class CmdLnDecoder {
    private Grib2JpegDecoder dec;
    private ParameterList defpl;
    private ParameterList pl;

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public CmdLnDecoder(java.lang.String[] r13) {
        /* JADX: method processing error */
/*
Error: jadx.core.utils.exceptions.JadxRuntimeException: Can't find block by offset: 0x00fd in list [B:41:0x0172]
	at jadx.core.utils.BlockUtils.getBlockByOffset(BlockUtils.java:43)
	at jadx.core.dex.instructions.IfNode.initBlocks(IfNode.java:60)
	at jadx.core.dex.visitors.blocksmaker.BlockFinish.initBlocksInIfNodes(BlockFinish.java:48)
	at jadx.core.dex.visitors.blocksmaker.BlockFinish.visit(BlockFinish.java:33)
	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:31)
	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:17)
	at jadx.core.ProcessClass.process(ProcessClass.java:34)
	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:282)
	at jadx.api.JavaClass.decompile(JavaClass.java:62)
	at jadx.api.JadxDecompiler.lambda$appendSourcesSave$0(JadxDecompiler.java:200)
	at jadx.api.JadxDecompiler$$Lambda$8/1122805102.run(Unknown Source)
*/
        /*
        r12 = this;
        r11 = 3;
        r12.<init>();
        r8 = new jj2000.j2k.util.ParameterList;
        r8.<init>();
        r12.defpl = r8;
        r6 = jj2000.j2k.decoder.Grib2JpegDecoder.getAllParameters();
        r8 = r6.length;
        r2 = r8 + -1;
    L_0x0012:
        if (r2 < 0) goto L_0x002b;
    L_0x0014:
        r8 = r6[r2];
        r8 = r8[r11];
        if (r8 == 0) goto L_0x0028;
    L_0x001a:
        r8 = r12.defpl;
        r9 = r6[r2];
        r10 = 0;
        r9 = r9[r10];
        r10 = r6[r2];
        r10 = r10[r11];
        r8.put(r9, r10);
    L_0x0028:
        r2 = r2 + -1;
        goto L_0x0012;
    L_0x002b:
        r8 = new jj2000.j2k.util.ParameterList;
        r9 = r12.defpl;
        r8.<init>(r9);
        r12.pl = r8;
        r8 = r13.length;
        if (r8 != 0) goto L_0x003f;
    L_0x0037:
        r8 = new java.lang.IllegalArgumentException;
        r9 = "No arguments!";
        r8.<init>(r9);
        throw r8;
    L_0x003f:
        r8 = r12.pl;	 Catch:{ StringFormatException -> 0x00e0 }
        r8.parseArgs(r13);	 Catch:{ StringFormatException -> 0x00e0 }
        r8 = r12.pl;
        r9 = "pfile";
        r8 = r8.getParameter(r9);
        if (r8 == 0) goto L_0x006d;
    L_0x004e:
        r3 = new java.io.FileInputStream;	 Catch:{ FileNotFoundException -> 0x00fe, IOException -> 0x0120 }
        r8 = r12.pl;	 Catch:{ FileNotFoundException -> 0x00fe, IOException -> 0x0120 }
        r9 = "pfile";	 Catch:{ FileNotFoundException -> 0x00fe, IOException -> 0x0120 }
        r8 = r8.getParameter(r9);	 Catch:{ FileNotFoundException -> 0x00fe, IOException -> 0x0120 }
        r3.<init>(r8);	 Catch:{ FileNotFoundException -> 0x00fe, IOException -> 0x0120 }
        r4 = new java.io.BufferedInputStream;	 Catch:{ FileNotFoundException -> 0x00fe, IOException -> 0x0120 }
        r4.<init>(r3);	 Catch:{ FileNotFoundException -> 0x00fe, IOException -> 0x0120 }
        r8 = r12.pl;	 Catch:{ FileNotFoundException -> 0x00fe, IOException -> 0x0120 }
        r8.load(r4);	 Catch:{ FileNotFoundException -> 0x00fe, IOException -> 0x0120 }
        r4.close();	 Catch:{ IOException -> 0x0142 }
    L_0x0068:
        r8 = r12.pl;	 Catch:{ StringFormatException -> 0x014c }
        r8.parseArgs(r13);	 Catch:{ StringFormatException -> 0x014c }
    L_0x006d:
        r8 = new jj2000.j2k.decoder.Grib2JpegDecoder;
        r8.<init>(r13);
        r12.dec = r8;
        r8 = r12.dec;
        r8 = r8.getExitCode();
        if (r8 == 0) goto L_0x0085;
    L_0x007c:
        r8 = r12.dec;
        r8 = r8.getExitCode();
        java.lang.System.exit(r8);
    L_0x0085:
        r8 = java.lang.System.out;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r9 = "raf processing CmdLnDecoder";	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r8.println(r9);	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r7 = new ucar.unidata.io.RandomAccessFile;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r8 = "/home/rkambic/jpeg2000/test/eta.j2k";	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r9 = "r";	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r7.<init>(r8, r9);	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r8 = r12.dec;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r10 = r7.length();	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r9 = (int) r10;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r8.decode(r7, r9);	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r8 = r12.dec;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r5 = r8.getPackBytes();	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r8 = r12.dec;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r0 = r8.getGdata();	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r2 = 0;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
    L_0x00ac:
        r8 = r0.length;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        if (r2 >= r8) goto L_0x016a;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
    L_0x00af:
        r8 = java.lang.System.out;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r9 = new java.lang.StringBuilder;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r9.<init>();	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r10 = "data[ ";	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r9 = r9.append(r10);	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r10 = r2 / 2;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r9 = r9.append(r10);	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r10 = " ] = ";	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r9 = r9.append(r10);	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r10 = r0[r2];	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r11 = r2 + 1;	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r11 = r0[r11];	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r10 = ucar.grib.GribNumbers.int2(r10, r11);	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r9 = r9.append(r10);	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r9 = r9.toString();	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r8.println(r9);	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r2 = r2 + 2;
        goto L_0x00ac;
    L_0x00e0:
        r1 = move-exception;
        r8 = java.lang.System.err;
        r9 = new java.lang.StringBuilder;
        r9.<init>();
        r10 = "An error occured while parsing the arguments:\n";
        r9 = r9.append(r10);
        r10 = r1.getMessage();
        r9 = r9.append(r10);
        r9 = r9.toString();
        r8.println(r9);
    L_0x00fd:
        return;
    L_0x00fe:
        r1 = move-exception;
        r8 = java.lang.System.err;
        r9 = new java.lang.StringBuilder;
        r9.<init>();
        r10 = "Could not load the argument file ";
        r9 = r9.append(r10);
        r10 = r12.pl;
        r11 = "pfile";
        r10 = r10.getParameter(r11);
        r9 = r9.append(r10);
        r9 = r9.toString();
        r8.println(r9);
        goto L_0x00fd;
    L_0x0120:
        r1 = move-exception;
        r8 = java.lang.System.err;
        r9 = new java.lang.StringBuilder;
        r9.<init>();
        r10 = "An error ocurred while reading from the argument file ";
        r9 = r9.append(r10);
        r10 = r12.pl;
        r11 = "pfile";
        r10 = r10.getParameter(r11);
        r9 = r9.append(r10);
        r9 = r9.toString();
        r8.println(r9);
        goto L_0x00fd;
    L_0x0142:
        r1 = move-exception;
        r8 = java.lang.System.out;
        r9 = "[WARNING]: Could not close the argument file after reading";
        r8.println(r9);
        goto L_0x0068;
    L_0x014c:
        r1 = move-exception;
        r8 = java.lang.System.err;
        r9 = new java.lang.StringBuilder;
        r9.<init>();
        r10 = "An error occured while re-parsing the arguments:\n";
        r9 = r9.append(r10);
        r10 = r1.getMessage();
        r9 = r9.append(r10);
        r9 = r9.toString();
        r8.println(r9);
        goto L_0x00fd;
    L_0x016a:
        r8 = r12.dec;
        r8 = r8.getExitCode();
        if (r8 == 0) goto L_0x00fd;
    L_0x0172:
        r8 = r12.dec;
        r8 = r8.getExitCode();
        java.lang.System.exit(r8);
        goto L_0x00fd;
    L_0x017c:
        r1 = move-exception;
        r8 = r12.dec;
        r8 = r8.getExitCode();
        if (r8 == 0) goto L_0x00fd;
    L_0x0185:
        r8 = r12.dec;
        r8 = r8.getExitCode();
        java.lang.System.exit(r8);
        goto L_0x00fd;
    L_0x0190:
        r1 = move-exception;
        r1.printStackTrace();	 Catch:{ IOException -> 0x017c, Throwable -> 0x0190, all -> 0x01a7 }
        r8 = r12.dec;
        r8 = r8.getExitCode();
        if (r8 == 0) goto L_0x00fd;
    L_0x019c:
        r8 = r12.dec;
        r8 = r8.getExitCode();
        java.lang.System.exit(r8);
        goto L_0x00fd;
    L_0x01a7:
        r8 = move-exception;
        r9 = r12.dec;
        r9 = r9.getExitCode();
        if (r9 == 0) goto L_0x01b9;
    L_0x01b0:
        r9 = r12.dec;
        r9 = r9.getExitCode();
        java.lang.System.exit(r9);
    L_0x01b9:
        throw r8;
        */
        throw new UnsupportedOperationException("Method not decompiled: jj2000.j2k.decoder.CmdLnDecoder.<init>(java.lang.String[]):void");
    }

    public static void main(String[] argv) {
        if (argv.length == 0) {
            FacilityManager.getMsgLogger().println("CmdLnDecoder: JJ2000's JPEG 2000 Decoder\n    use jj2000.j2k.decoder.CmdLnDecoder -u to get help\n", 0, 0);
            System.exit(1);
        }
        CmdLnDecoder cmdLnDecoder = new CmdLnDecoder(argv);
    }
}
