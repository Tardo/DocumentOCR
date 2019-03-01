package com.jcraft.jzlib;

import java.io.ByteArrayOutputStream;

final class Inflate {
    private static final int BAD = 13;
    private static final int BLOCKS = 7;
    private static final int CHECK1 = 11;
    private static final int CHECK2 = 10;
    private static final int CHECK3 = 9;
    private static final int CHECK4 = 8;
    private static final int COMMENT = 21;
    private static final int DICT0 = 6;
    private static final int DICT1 = 5;
    private static final int DICT2 = 4;
    private static final int DICT3 = 3;
    private static final int DICT4 = 2;
    private static final int DONE = 12;
    private static final int EXLEN = 18;
    private static final int EXTRA = 19;
    private static final int FLAG = 1;
    private static final int FLAGS = 23;
    private static final int HCRC = 22;
    private static final int HEAD = 14;
    private static final int LENGTH = 15;
    private static final int MAX_WBITS = 15;
    private static final int METHOD = 0;
    private static final int NAME = 20;
    private static final int OS = 17;
    private static final int PRESET_DICT = 32;
    private static final int TIME = 16;
    private static final int Z_BUF_ERROR = -5;
    private static final int Z_DATA_ERROR = -3;
    private static final int Z_DEFLATED = 8;
    private static final int Z_ERRNO = -1;
    static final int Z_FINISH = 4;
    static final int Z_FULL_FLUSH = 3;
    private static final int Z_MEM_ERROR = -4;
    private static final int Z_NEED_DICT = 2;
    static final int Z_NO_FLUSH = 0;
    private static final int Z_OK = 0;
    static final int Z_PARTIAL_FLUSH = 1;
    private static final int Z_STREAM_END = 1;
    private static final int Z_STREAM_ERROR = -2;
    static final int Z_SYNC_FLUSH = 2;
    private static final int Z_VERSION_ERROR = -6;
    private static byte[] mark = new byte[]{(byte) 0, (byte) 0, (byte) -1, (byte) -1};
    InfBlocks blocks;
    private byte[] crcbuf = new byte[4];
    private int flags;
    GZIPHeader gheader = null;
    int marker;
    int method;
    int mode;
    long need;
    private int need_bytes = -1;
    private ByteArrayOutputStream tmp_string = null;
    long was = -1;
    int wbits;
    int wrap;
    /* renamed from: z */
    private final ZStream f11z;

    class Return extends Exception {
        /* renamed from: r */
        int f10r;

        Return(int r) {
            this.f10r = r;
        }
    }

    int inflateReset() {
        if (this.f11z == null) {
            return -2;
        }
        ZStream zStream = this.f11z;
        this.f11z.total_out = 0;
        zStream.total_in = 0;
        this.f11z.msg = null;
        this.mode = 14;
        this.need_bytes = -1;
        this.blocks.reset();
        return 0;
    }

    int inflateEnd() {
        if (this.blocks != null) {
            this.blocks.free();
        }
        return 0;
    }

    Inflate(ZStream z) {
        this.f11z = z;
    }

    int inflateInit(int w) {
        this.f11z.msg = null;
        this.blocks = null;
        this.wrap = 0;
        if (w < 0) {
            w = -w;
        } else {
            this.wrap = (w >> 4) + 1;
            if (w < 48) {
                w &= 15;
            }
        }
        if (w < 8 || w > 15) {
            inflateEnd();
            return -2;
        }
        if (!(this.blocks == null || this.wbits == w)) {
            this.blocks.free();
            this.blocks = null;
        }
        this.wbits = w;
        this.blocks = new InfBlocks(this.f11z, 1 << w);
        inflateReset();
        return 0;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    int inflate(int r13) {
        /*
        r12 = this;
        r3 = 0;
        r5 = r12.f11z;
        if (r5 == 0) goto L_0x000b;
    L_0x0005:
        r5 = r12.f11z;
        r5 = r5.next_in;
        if (r5 != 0) goto L_0x0018;
    L_0x000b:
        r5 = 4;
        if (r13 != r5) goto L_0x0016;
    L_0x000e:
        r5 = r12.mode;
        r6 = 14;
        if (r5 != r6) goto L_0x0016;
    L_0x0014:
        r4 = 0;
    L_0x0015:
        return r4;
    L_0x0016:
        r4 = -2;
        goto L_0x0015;
    L_0x0018:
        r5 = 4;
        if (r13 != r5) goto L_0x0024;
    L_0x001b:
        r13 = -5;
    L_0x001c:
        r4 = -5;
    L_0x001d:
        r5 = r12.mode;
        switch(r5) {
            case 2: goto L_0x00d0;
            case 3: goto L_0x0106;
            case 4: goto L_0x013d;
            case 5: goto L_0x0174;
            case 6: goto L_0x01b2;
            case 7: goto L_0x01c2;
            case 8: goto L_0x01f8;
            case 9: goto L_0x022f;
            case 10: goto L_0x0267;
            case 11: goto L_0x029f;
            case 12: goto L_0x0374;
            case 13: goto L_0x0392;
            case 14: goto L_0x0026;
            case 15: goto L_0x0313;
            case 16: goto L_0x03e0;
            case 17: goto L_0x03ff;
            case 18: goto L_0x042c;
            case 19: goto L_0x0458;
            case 20: goto L_0x0485;
            case 21: goto L_0x04a4;
            case 22: goto L_0x04c3;
            case 23: goto L_0x0395;
            default: goto L_0x0022;
        };
    L_0x0022:
        r4 = -2;
        goto L_0x0015;
    L_0x0024:
        r13 = 0;
        goto L_0x001c;
    L_0x0026:
        r5 = r12.wrap;
        if (r5 != 0) goto L_0x002e;
    L_0x002a:
        r5 = 7;
        r12.mode = r5;
        goto L_0x001d;
    L_0x002e:
        r5 = 2;
        r4 = r12.readBytes(r5, r4, r13);	 Catch:{ Return -> 0x0061 }
        r5 = r12.wrap;
        r5 = r5 & 2;
        if (r5 == 0) goto L_0x0065;
    L_0x0039:
        r6 = r12.need;
        r8 = 35615; // 0x8b1f float:4.9907E-41 double:1.7596E-319;
        r5 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1));
        if (r5 != 0) goto L_0x0065;
    L_0x0042:
        r5 = r12.f11z;
        r6 = new com.jcraft.jzlib.CRC32;
        r6.<init>();
        r5.adler = r6;
        r5 = 2;
        r6 = r12.need;
        r12.checksum(r5, r6);
        r5 = r12.gheader;
        if (r5 != 0) goto L_0x005c;
    L_0x0055:
        r5 = new com.jcraft.jzlib.GZIPHeader;
        r5.<init>();
        r12.gheader = r5;
    L_0x005c:
        r5 = 23;
        r12.mode = r5;
        goto L_0x001d;
    L_0x0061:
        r1 = move-exception;
        r4 = r1.f10r;
        goto L_0x0015;
    L_0x0065:
        r5 = 0;
        r12.flags = r5;
        r6 = r12.need;
        r5 = (int) r6;
        r5 = r5 & 255;
        r12.method = r5;
        r6 = r12.need;
        r5 = 8;
        r6 = r6 >> r5;
        r5 = (int) r6;
        r0 = r5 & 255;
        r5 = r12.wrap;
        r5 = r5 & 1;
        if (r5 == 0) goto L_0x0086;
    L_0x007d:
        r5 = r12.method;
        r5 = r5 << 8;
        r5 = r5 + r0;
        r5 = r5 % 31;
        if (r5 == 0) goto L_0x0091;
    L_0x0086:
        r5 = 13;
        r12.mode = r5;
        r5 = r12.f11z;
        r6 = "incorrect header check";
        r5.msg = r6;
        goto L_0x001d;
    L_0x0091:
        r5 = r12.method;
        r5 = r5 & 15;
        r6 = 8;
        if (r5 == r6) goto L_0x00a5;
    L_0x0099:
        r5 = 13;
        r12.mode = r5;
        r5 = r12.f11z;
        r6 = "unknown compression method";
        r5.msg = r6;
        goto L_0x001d;
    L_0x00a5:
        r5 = r12.method;
        r5 = r5 >> 4;
        r5 = r5 + 8;
        r6 = r12.wbits;
        if (r5 <= r6) goto L_0x00bb;
    L_0x00af:
        r5 = 13;
        r12.mode = r5;
        r5 = r12.f11z;
        r6 = "invalid window size";
        r5.msg = r6;
        goto L_0x001d;
    L_0x00bb:
        r5 = r12.f11z;
        r6 = new com.jcraft.jzlib.Adler32;
        r6.<init>();
        r5.adler = r6;
        r5 = r0 & 32;
        if (r5 != 0) goto L_0x00cd;
    L_0x00c8:
        r5 = 7;
        r12.mode = r5;
        goto L_0x001d;
    L_0x00cd:
        r5 = 2;
        r12.mode = r5;
    L_0x00d0:
        r5 = r12.f11z;
        r5 = r5.avail_in;
        if (r5 == 0) goto L_0x0015;
    L_0x00d6:
        r4 = r13;
        r5 = r12.f11z;
        r6 = r5.avail_in;
        r6 = r6 + -1;
        r5.avail_in = r6;
        r5 = r12.f11z;
        r6 = r5.total_in;
        r8 = 1;
        r6 = r6 + r8;
        r5.total_in = r6;
        r5 = r12.f11z;
        r5 = r5.next_in;
        r6 = r12.f11z;
        r7 = r6.next_in_index;
        r8 = r7 + 1;
        r6.next_in_index = r8;
        r5 = r5[r7];
        r5 = r5 & 255;
        r5 = r5 << 24;
        r6 = (long) r5;
        r8 = 4278190080; // 0xff000000 float:-1.7014118E38 double:2.113706745E-314;
        r6 = r6 & r8;
        r12.need = r6;
        r5 = 3;
        r12.mode = r5;
    L_0x0106:
        r5 = r12.f11z;
        r5 = r5.avail_in;
        if (r5 == 0) goto L_0x0015;
    L_0x010c:
        r4 = r13;
        r5 = r12.f11z;
        r6 = r5.avail_in;
        r6 = r6 + -1;
        r5.avail_in = r6;
        r5 = r12.f11z;
        r6 = r5.total_in;
        r8 = 1;
        r6 = r6 + r8;
        r5.total_in = r6;
        r6 = r12.need;
        r5 = r12.f11z;
        r5 = r5.next_in;
        r8 = r12.f11z;
        r9 = r8.next_in_index;
        r10 = r9 + 1;
        r8.next_in_index = r10;
        r5 = r5[r9];
        r5 = r5 & 255;
        r5 = r5 << 16;
        r8 = (long) r5;
        r10 = 16711680; // 0xff0000 float:2.3418052E-38 double:8.256667E-317;
        r8 = r8 & r10;
        r6 = r6 + r8;
        r12.need = r6;
        r5 = 4;
        r12.mode = r5;
    L_0x013d:
        r5 = r12.f11z;
        r5 = r5.avail_in;
        if (r5 == 0) goto L_0x0015;
    L_0x0143:
        r4 = r13;
        r5 = r12.f11z;
        r6 = r5.avail_in;
        r6 = r6 + -1;
        r5.avail_in = r6;
        r5 = r12.f11z;
        r6 = r5.total_in;
        r8 = 1;
        r6 = r6 + r8;
        r5.total_in = r6;
        r6 = r12.need;
        r5 = r12.f11z;
        r5 = r5.next_in;
        r8 = r12.f11z;
        r9 = r8.next_in_index;
        r10 = r9 + 1;
        r8.next_in_index = r10;
        r5 = r5[r9];
        r5 = r5 & 255;
        r5 = r5 << 8;
        r8 = (long) r5;
        r10 = 65280; // 0xff00 float:9.1477E-41 double:3.22526E-319;
        r8 = r8 & r10;
        r6 = r6 + r8;
        r12.need = r6;
        r5 = 5;
        r12.mode = r5;
    L_0x0174:
        r5 = r12.f11z;
        r5 = r5.avail_in;
        if (r5 == 0) goto L_0x0015;
    L_0x017a:
        r4 = r13;
        r5 = r12.f11z;
        r6 = r5.avail_in;
        r6 = r6 + -1;
        r5.avail_in = r6;
        r5 = r12.f11z;
        r6 = r5.total_in;
        r8 = 1;
        r6 = r6 + r8;
        r5.total_in = r6;
        r6 = r12.need;
        r5 = r12.f11z;
        r5 = r5.next_in;
        r8 = r12.f11z;
        r9 = r8.next_in_index;
        r10 = r9 + 1;
        r8.next_in_index = r10;
        r5 = r5[r9];
        r8 = (long) r5;
        r10 = 255; // 0xff float:3.57E-43 double:1.26E-321;
        r8 = r8 & r10;
        r6 = r6 + r8;
        r12.need = r6;
        r5 = r12.f11z;
        r5 = r5.adler;
        r6 = r12.need;
        r5.reset(r6);
        r5 = 6;
        r12.mode = r5;
        r4 = 2;
        goto L_0x0015;
    L_0x01b2:
        r5 = 13;
        r12.mode = r5;
        r5 = r12.f11z;
        r6 = "need dictionary";
        r5.msg = r6;
        r5 = 0;
        r12.marker = r5;
        r4 = -2;
        goto L_0x0015;
    L_0x01c2:
        r5 = r12.blocks;
        r4 = r5.proc(r4);
        r5 = -3;
        if (r4 != r5) goto L_0x01d4;
    L_0x01cb:
        r5 = 13;
        r12.mode = r5;
        r5 = 0;
        r12.marker = r5;
        goto L_0x001d;
    L_0x01d4:
        if (r4 != 0) goto L_0x01d7;
    L_0x01d6:
        r4 = r13;
    L_0x01d7:
        r5 = 1;
        if (r4 != r5) goto L_0x0015;
    L_0x01da:
        r4 = r13;
        r5 = r12.f11z;
        r5 = r5.adler;
        r6 = r5.getValue();
        r12.was = r6;
        r5 = r12.blocks;
        r5.reset();
        r5 = r12.wrap;
        if (r5 != 0) goto L_0x01f4;
    L_0x01ee:
        r5 = 12;
        r12.mode = r5;
        goto L_0x001d;
    L_0x01f4:
        r5 = 8;
        r12.mode = r5;
    L_0x01f8:
        r5 = r12.f11z;
        r5 = r5.avail_in;
        if (r5 == 0) goto L_0x0015;
    L_0x01fe:
        r4 = r13;
        r5 = r12.f11z;
        r6 = r5.avail_in;
        r6 = r6 + -1;
        r5.avail_in = r6;
        r5 = r12.f11z;
        r6 = r5.total_in;
        r8 = 1;
        r6 = r6 + r8;
        r5.total_in = r6;
        r5 = r12.f11z;
        r5 = r5.next_in;
        r6 = r12.f11z;
        r7 = r6.next_in_index;
        r8 = r7 + 1;
        r6.next_in_index = r8;
        r5 = r5[r7];
        r5 = r5 & 255;
        r5 = r5 << 24;
        r6 = (long) r5;
        r8 = 4278190080; // 0xff000000 float:-1.7014118E38 double:2.113706745E-314;
        r6 = r6 & r8;
        r12.need = r6;
        r5 = 9;
        r12.mode = r5;
    L_0x022f:
        r5 = r12.f11z;
        r5 = r5.avail_in;
        if (r5 == 0) goto L_0x0015;
    L_0x0235:
        r4 = r13;
        r5 = r12.f11z;
        r6 = r5.avail_in;
        r6 = r6 + -1;
        r5.avail_in = r6;
        r5 = r12.f11z;
        r6 = r5.total_in;
        r8 = 1;
        r6 = r6 + r8;
        r5.total_in = r6;
        r6 = r12.need;
        r5 = r12.f11z;
        r5 = r5.next_in;
        r8 = r12.f11z;
        r9 = r8.next_in_index;
        r10 = r9 + 1;
        r8.next_in_index = r10;
        r5 = r5[r9];
        r5 = r5 & 255;
        r5 = r5 << 16;
        r8 = (long) r5;
        r10 = 16711680; // 0xff0000 float:2.3418052E-38 double:8.256667E-317;
        r8 = r8 & r10;
        r6 = r6 + r8;
        r12.need = r6;
        r5 = 10;
        r12.mode = r5;
    L_0x0267:
        r5 = r12.f11z;
        r5 = r5.avail_in;
        if (r5 == 0) goto L_0x0015;
    L_0x026d:
        r4 = r13;
        r5 = r12.f11z;
        r6 = r5.avail_in;
        r6 = r6 + -1;
        r5.avail_in = r6;
        r5 = r12.f11z;
        r6 = r5.total_in;
        r8 = 1;
        r6 = r6 + r8;
        r5.total_in = r6;
        r6 = r12.need;
        r5 = r12.f11z;
        r5 = r5.next_in;
        r8 = r12.f11z;
        r9 = r8.next_in_index;
        r10 = r9 + 1;
        r8.next_in_index = r10;
        r5 = r5[r9];
        r5 = r5 & 255;
        r5 = r5 << 8;
        r8 = (long) r5;
        r10 = 65280; // 0xff00 float:9.1477E-41 double:3.22526E-319;
        r8 = r8 & r10;
        r6 = r6 + r8;
        r12.need = r6;
        r5 = 11;
        r12.mode = r5;
    L_0x029f:
        r5 = r12.f11z;
        r5 = r5.avail_in;
        if (r5 == 0) goto L_0x0015;
    L_0x02a5:
        r4 = r13;
        r5 = r12.f11z;
        r6 = r5.avail_in;
        r6 = r6 + -1;
        r5.avail_in = r6;
        r5 = r12.f11z;
        r6 = r5.total_in;
        r8 = 1;
        r6 = r6 + r8;
        r5.total_in = r6;
        r6 = r12.need;
        r5 = r12.f11z;
        r5 = r5.next_in;
        r8 = r12.f11z;
        r9 = r8.next_in_index;
        r10 = r9 + 1;
        r8.next_in_index = r10;
        r5 = r5[r9];
        r8 = (long) r5;
        r10 = 255; // 0xff float:3.57E-43 double:1.26E-321;
        r8 = r8 & r10;
        r6 = r6 + r8;
        r12.need = r6;
        r5 = r12.flags;
        if (r5 == 0) goto L_0x0301;
    L_0x02d2:
        r6 = r12.need;
        r8 = -16777216; // 0xffffffffff000000 float:-1.7014118E38 double:NaN;
        r6 = r6 & r8;
        r5 = 24;
        r6 = r6 >> r5;
        r8 = r12.need;
        r10 = 16711680; // 0xff0000 float:2.3418052E-38 double:8.256667E-317;
        r8 = r8 & r10;
        r5 = 8;
        r8 = r8 >> r5;
        r6 = r6 | r8;
        r8 = r12.need;
        r10 = 65280; // 0xff00 float:9.1477E-41 double:3.22526E-319;
        r8 = r8 & r10;
        r5 = 8;
        r8 = r8 << r5;
        r6 = r6 | r8;
        r8 = r12.need;
        r10 = 65535; // 0xffff float:9.1834E-41 double:3.23786E-319;
        r8 = r8 & r10;
        r5 = 24;
        r8 = r8 << r5;
        r6 = r6 | r8;
        r8 = 4294967295; // 0xffffffff float:NaN double:2.1219957905E-314;
        r6 = r6 & r8;
        r12.need = r6;
    L_0x0301:
        r6 = r12.was;
        r5 = (int) r6;
        r6 = r12.need;
        r6 = (int) r6;
        if (r5 == r6) goto L_0x033b;
    L_0x0309:
        r5 = r12.f11z;
        r6 = "incorrect data check";
        r5.msg = r6;
    L_0x030f:
        r5 = 15;
        r12.mode = r5;
    L_0x0313:
        r5 = r12.wrap;
        if (r5 == 0) goto L_0x0377;
    L_0x0317:
        r5 = r12.flags;
        if (r5 == 0) goto L_0x0377;
    L_0x031b:
        r5 = 4;
        r4 = r12.readBytes(r5, r4, r13);	 Catch:{ Return -> 0x034a }
        r5 = r12.f11z;
        r5 = r5.msg;
        if (r5 == 0) goto L_0x034f;
    L_0x0326:
        r5 = r12.f11z;
        r5 = r5.msg;
        r6 = "incorrect data check";
        r5 = r5.equals(r6);
        if (r5 == 0) goto L_0x034f;
    L_0x0332:
        r5 = 13;
        r12.mode = r5;
        r5 = 5;
        r12.marker = r5;
        goto L_0x001d;
    L_0x033b:
        r5 = r12.flags;
        if (r5 == 0) goto L_0x030f;
    L_0x033f:
        r5 = r12.gheader;
        if (r5 == 0) goto L_0x030f;
    L_0x0343:
        r5 = r12.gheader;
        r6 = r12.need;
        r5.crc = r6;
        goto L_0x030f;
    L_0x034a:
        r1 = move-exception;
        r4 = r1.f10r;
        goto L_0x0015;
    L_0x034f:
        r6 = r12.need;
        r5 = r12.f11z;
        r8 = r5.total_out;
        r10 = 4294967295; // 0xffffffff float:NaN double:2.1219957905E-314;
        r8 = r8 & r10;
        r5 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1));
        if (r5 == 0) goto L_0x036b;
    L_0x035f:
        r5 = r12.f11z;
        r6 = "incorrect length check";
        r5.msg = r6;
        r5 = 13;
        r12.mode = r5;
        goto L_0x001d;
    L_0x036b:
        r5 = r12.f11z;
        r6 = 0;
        r5.msg = r6;
    L_0x0370:
        r5 = 12;
        r12.mode = r5;
    L_0x0374:
        r4 = 1;
        goto L_0x0015;
    L_0x0377:
        r5 = r12.f11z;
        r5 = r5.msg;
        if (r5 == 0) goto L_0x0370;
    L_0x037d:
        r5 = r12.f11z;
        r5 = r5.msg;
        r6 = "incorrect data check";
        r5 = r5.equals(r6);
        if (r5 == 0) goto L_0x0370;
    L_0x0389:
        r5 = 13;
        r12.mode = r5;
        r5 = 5;
        r12.marker = r5;
        goto L_0x001d;
    L_0x0392:
        r4 = -3;
        goto L_0x0015;
    L_0x0395:
        r5 = 2;
        r4 = r12.readBytes(r5, r4, r13);	 Catch:{ Return -> 0x03b7 }
        r6 = r12.need;
        r5 = (int) r6;
        r6 = 65535; // 0xffff float:9.1834E-41 double:3.23786E-319;
        r5 = r5 & r6;
        r12.flags = r5;
        r5 = r12.flags;
        r5 = r5 & 255;
        r6 = 8;
        if (r5 == r6) goto L_0x03bc;
    L_0x03ab:
        r5 = r12.f11z;
        r6 = "unknown compression method";
        r5.msg = r6;
        r5 = 13;
        r12.mode = r5;
        goto L_0x001d;
    L_0x03b7:
        r1 = move-exception;
        r4 = r1.f10r;
        goto L_0x0015;
    L_0x03bc:
        r5 = r12.flags;
        r6 = 57344; // 0xe000 float:8.0356E-41 double:2.83317E-319;
        r5 = r5 & r6;
        if (r5 == 0) goto L_0x03d0;
    L_0x03c4:
        r5 = r12.f11z;
        r6 = "unknown header flags set";
        r5.msg = r6;
        r5 = 13;
        r12.mode = r5;
        goto L_0x001d;
    L_0x03d0:
        r5 = r12.flags;
        r5 = r5 & 512;
        if (r5 == 0) goto L_0x03dc;
    L_0x03d6:
        r5 = 2;
        r6 = r12.need;
        r12.checksum(r5, r6);
    L_0x03dc:
        r5 = 16;
        r12.mode = r5;
    L_0x03e0:
        r5 = 4;
        r4 = r12.readBytes(r5, r4, r13);	 Catch:{ Return -> 0x04fe }
        r5 = r12.gheader;
        if (r5 == 0) goto L_0x03ef;
    L_0x03e9:
        r5 = r12.gheader;
        r6 = r12.need;
        r5.time = r6;
    L_0x03ef:
        r5 = r12.flags;
        r5 = r5 & 512;
        if (r5 == 0) goto L_0x03fb;
    L_0x03f5:
        r5 = 4;
        r6 = r12.need;
        r12.checksum(r5, r6);
    L_0x03fb:
        r5 = 17;
        r12.mode = r5;
    L_0x03ff:
        r5 = 2;
        r4 = r12.readBytes(r5, r4, r13);	 Catch:{ Return -> 0x0503 }
        r5 = r12.gheader;
        if (r5 == 0) goto L_0x041c;
    L_0x0408:
        r5 = r12.gheader;
        r6 = r12.need;
        r6 = (int) r6;
        r6 = r6 & 255;
        r5.xflags = r6;
        r5 = r12.gheader;
        r6 = r12.need;
        r6 = (int) r6;
        r6 = r6 >> 8;
        r6 = r6 & 255;
        r5.os = r6;
    L_0x041c:
        r5 = r12.flags;
        r5 = r5 & 512;
        if (r5 == 0) goto L_0x0428;
    L_0x0422:
        r5 = 2;
        r6 = r12.need;
        r12.checksum(r5, r6);
    L_0x0428:
        r5 = 18;
        r12.mode = r5;
    L_0x042c:
        r5 = r12.flags;
        r5 = r5 & 1024;
        if (r5 == 0) goto L_0x050d;
    L_0x0432:
        r5 = 2;
        r4 = r12.readBytes(r5, r4, r13);	 Catch:{ Return -> 0x0508 }
        r5 = r12.gheader;
        if (r5 == 0) goto L_0x0448;
    L_0x043b:
        r5 = r12.gheader;
        r6 = r12.need;
        r6 = (int) r6;
        r7 = 65535; // 0xffff float:9.1834E-41 double:3.23786E-319;
        r6 = r6 & r7;
        r6 = new byte[r6];
        r5.extra = r6;
    L_0x0448:
        r5 = r12.flags;
        r5 = r5 & 512;
        if (r5 == 0) goto L_0x0454;
    L_0x044e:
        r5 = 2;
        r6 = r12.need;
        r12.checksum(r5, r6);
    L_0x0454:
        r5 = 19;
        r12.mode = r5;
    L_0x0458:
        r5 = r12.flags;
        r5 = r5 & 1024;
        if (r5 == 0) goto L_0x0529;
    L_0x045e:
        r4 = r12.readBytes(r4, r13);	 Catch:{ Return -> 0x0524 }
        r5 = r12.gheader;	 Catch:{ Return -> 0x0524 }
        if (r5 == 0) goto L_0x0481;
    L_0x0466:
        r5 = r12.tmp_string;	 Catch:{ Return -> 0x0524 }
        r2 = r5.toByteArray();	 Catch:{ Return -> 0x0524 }
        r5 = 0;
        r12.tmp_string = r5;	 Catch:{ Return -> 0x0524 }
        r5 = r2.length;	 Catch:{ Return -> 0x0524 }
        r6 = r12.gheader;	 Catch:{ Return -> 0x0524 }
        r6 = r6.extra;	 Catch:{ Return -> 0x0524 }
        r6 = r6.length;	 Catch:{ Return -> 0x0524 }
        if (r5 != r6) goto L_0x0518;
    L_0x0477:
        r5 = 0;
        r6 = r12.gheader;	 Catch:{ Return -> 0x0524 }
        r6 = r6.extra;	 Catch:{ Return -> 0x0524 }
        r7 = 0;
        r8 = r2.length;	 Catch:{ Return -> 0x0524 }
        java.lang.System.arraycopy(r2, r5, r6, r7, r8);	 Catch:{ Return -> 0x0524 }
    L_0x0481:
        r5 = 20;
        r12.mode = r5;
    L_0x0485:
        r5 = r12.flags;
        r5 = r5 & 2048;
        if (r5 == 0) goto L_0x0539;
    L_0x048b:
        r4 = r12.readString(r4, r13);	 Catch:{ Return -> 0x0534 }
        r5 = r12.gheader;	 Catch:{ Return -> 0x0534 }
        if (r5 == 0) goto L_0x049d;
    L_0x0493:
        r5 = r12.gheader;	 Catch:{ Return -> 0x0534 }
        r6 = r12.tmp_string;	 Catch:{ Return -> 0x0534 }
        r6 = r6.toByteArray();	 Catch:{ Return -> 0x0534 }
        r5.name = r6;	 Catch:{ Return -> 0x0534 }
    L_0x049d:
        r5 = 0;
        r12.tmp_string = r5;	 Catch:{ Return -> 0x0534 }
    L_0x04a0:
        r5 = 21;
        r12.mode = r5;
    L_0x04a4:
        r5 = r12.flags;
        r5 = r5 & 4096;
        if (r5 == 0) goto L_0x0549;
    L_0x04aa:
        r4 = r12.readString(r4, r13);	 Catch:{ Return -> 0x0544 }
        r5 = r12.gheader;	 Catch:{ Return -> 0x0544 }
        if (r5 == 0) goto L_0x04bc;
    L_0x04b2:
        r5 = r12.gheader;	 Catch:{ Return -> 0x0544 }
        r6 = r12.tmp_string;	 Catch:{ Return -> 0x0544 }
        r6 = r6.toByteArray();	 Catch:{ Return -> 0x0544 }
        r5.comment = r6;	 Catch:{ Return -> 0x0544 }
    L_0x04bc:
        r5 = 0;
        r12.tmp_string = r5;	 Catch:{ Return -> 0x0544 }
    L_0x04bf:
        r5 = 22;
        r12.mode = r5;
    L_0x04c3:
        r5 = r12.flags;
        r5 = r5 & 512;
        if (r5 == 0) goto L_0x0559;
    L_0x04c9:
        r5 = 2;
        r4 = r12.readBytes(r5, r4, r13);	 Catch:{ Return -> 0x0554 }
        r5 = r12.gheader;
        if (r5 == 0) goto L_0x04dd;
    L_0x04d2:
        r5 = r12.gheader;
        r6 = r12.need;
        r8 = 65535; // 0xffff float:9.1834E-41 double:3.23786E-319;
        r6 = r6 & r8;
        r6 = (int) r6;
        r5.hcrc = r6;
    L_0x04dd:
        r6 = r12.need;
        r5 = r12.f11z;
        r5 = r5.adler;
        r8 = r5.getValue();
        r10 = 65535; // 0xffff float:9.1834E-41 double:3.23786E-319;
        r8 = r8 & r10;
        r5 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1));
        if (r5 == 0) goto L_0x0559;
    L_0x04ef:
        r5 = 13;
        r12.mode = r5;
        r5 = r12.f11z;
        r6 = "header crc mismatch";
        r5.msg = r6;
        r5 = 5;
        r12.marker = r5;
        goto L_0x001d;
    L_0x04fe:
        r1 = move-exception;
        r4 = r1.f10r;
        goto L_0x0015;
    L_0x0503:
        r1 = move-exception;
        r4 = r1.f10r;
        goto L_0x0015;
    L_0x0508:
        r1 = move-exception;
        r4 = r1.f10r;
        goto L_0x0015;
    L_0x050d:
        r5 = r12.gheader;
        if (r5 == 0) goto L_0x0454;
    L_0x0511:
        r5 = r12.gheader;
        r6 = 0;
        r5.extra = r6;
        goto L_0x0454;
    L_0x0518:
        r5 = r12.f11z;	 Catch:{ Return -> 0x0524 }
        r6 = "bad extra field length";
        r5.msg = r6;	 Catch:{ Return -> 0x0524 }
        r5 = 13;
        r12.mode = r5;	 Catch:{ Return -> 0x0524 }
        goto L_0x001d;
    L_0x0524:
        r1 = move-exception;
        r4 = r1.f10r;
        goto L_0x0015;
    L_0x0529:
        r5 = r12.gheader;
        if (r5 == 0) goto L_0x0481;
    L_0x052d:
        r5 = r12.gheader;
        r6 = 0;
        r5.extra = r6;
        goto L_0x0481;
    L_0x0534:
        r1 = move-exception;
        r4 = r1.f10r;
        goto L_0x0015;
    L_0x0539:
        r5 = r12.gheader;
        if (r5 == 0) goto L_0x04a0;
    L_0x053d:
        r5 = r12.gheader;
        r6 = 0;
        r5.name = r6;
        goto L_0x04a0;
    L_0x0544:
        r1 = move-exception;
        r4 = r1.f10r;
        goto L_0x0015;
    L_0x0549:
        r5 = r12.gheader;
        if (r5 == 0) goto L_0x04bf;
    L_0x054d:
        r5 = r12.gheader;
        r6 = 0;
        r5.comment = r6;
        goto L_0x04bf;
    L_0x0554:
        r1 = move-exception;
        r4 = r1.f10r;
        goto L_0x0015;
    L_0x0559:
        r5 = r12.f11z;
        r6 = new com.jcraft.jzlib.CRC32;
        r6.<init>();
        r5.adler = r6;
        r5 = 7;
        r12.mode = r5;
        goto L_0x001d;
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jcraft.jzlib.Inflate.inflate(int):int");
    }

    int inflateSetDictionary(byte[] dictionary, int dictLength) {
        if (this.f11z == null || (this.mode != 6 && this.wrap != 0)) {
            return -2;
        }
        int index = 0;
        int length = dictLength;
        if (this.mode == 6) {
            long adler_need = this.f11z.adler.getValue();
            this.f11z.adler.reset();
            this.f11z.adler.update(dictionary, 0, dictLength);
            if (this.f11z.adler.getValue() != adler_need) {
                return -3;
            }
        }
        this.f11z.adler.reset();
        if (length >= (1 << this.wbits)) {
            length = (1 << this.wbits) - 1;
            index = dictLength - length;
        }
        this.blocks.set_dictionary(dictionary, index, length);
        this.mode = 7;
        return 0;
    }

    int inflateSync() {
        if (this.f11z == null) {
            return -2;
        }
        if (this.mode != 13) {
            this.mode = 13;
            this.marker = 0;
        }
        int n = this.f11z.avail_in;
        if (n == 0) {
            return -5;
        }
        int p = this.f11z.next_in_index;
        int m = this.marker;
        while (n != 0 && m < 4) {
            if (this.f11z.next_in[p] == mark[m]) {
                m++;
            } else if (this.f11z.next_in[p] != (byte) 0) {
                m = 0;
            } else {
                m = 4 - m;
            }
            p++;
            n--;
        }
        ZStream zStream = this.f11z;
        zStream.total_in += (long) (p - this.f11z.next_in_index);
        this.f11z.next_in_index = p;
        this.f11z.avail_in = n;
        this.marker = m;
        if (m != 4) {
            return -3;
        }
        long r = this.f11z.total_in;
        long w = this.f11z.total_out;
        inflateReset();
        this.f11z.total_in = r;
        this.f11z.total_out = w;
        this.mode = 7;
        return 0;
    }

    int inflateSyncPoint() {
        if (this.f11z == null || this.blocks == null) {
            return -2;
        }
        return this.blocks.sync_point();
    }

    private int readBytes(int n, int r, int f) throws Return {
        if (this.need_bytes == -1) {
            this.need_bytes = n;
            this.need = 0;
        }
        while (this.need_bytes > 0) {
            if (this.f11z.avail_in == 0) {
                throw new Return(r);
            }
            r = f;
            ZStream zStream = this.f11z;
            zStream.avail_in--;
            zStream = this.f11z;
            zStream.total_in++;
            long j = this.need;
            byte[] bArr = this.f11z.next_in;
            ZStream zStream2 = this.f11z;
            int i = zStream2.next_in_index;
            zStream2.next_in_index = i + 1;
            this.need = j | ((long) ((bArr[i] & 255) << ((n - this.need_bytes) * 8)));
            this.need_bytes--;
        }
        if (n == 2) {
            this.need &= 65535;
        } else if (n == 4) {
            this.need &= 4294967295L;
        }
        this.need_bytes = -1;
        return r;
    }

    private int readString(int r, int f) throws Return {
        if (this.tmp_string == null) {
            this.tmp_string = new ByteArrayOutputStream();
        }
        while (this.f11z.avail_in != 0) {
            r = f;
            ZStream zStream = this.f11z;
            zStream.avail_in--;
            zStream = this.f11z;
            zStream.total_in++;
            int b = this.f11z.next_in[this.f11z.next_in_index];
            if (b != 0) {
                this.tmp_string.write(this.f11z.next_in, this.f11z.next_in_index, 1);
            }
            this.f11z.adler.update(this.f11z.next_in, this.f11z.next_in_index, 1);
            zStream = this.f11z;
            zStream.next_in_index++;
            if (b == 0) {
                return r;
            }
        }
        throw new Return(r);
    }

    private int readBytes(int r, int f) throws Return {
        if (this.tmp_string == null) {
            this.tmp_string = new ByteArrayOutputStream();
        }
        while (this.need > 0) {
            if (this.f11z.avail_in == 0) {
                throw new Return(r);
            }
            r = f;
            ZStream zStream = this.f11z;
            zStream.avail_in--;
            zStream = this.f11z;
            zStream.total_in++;
            int b = this.f11z.next_in[this.f11z.next_in_index];
            this.tmp_string.write(this.f11z.next_in, this.f11z.next_in_index, 1);
            this.f11z.adler.update(this.f11z.next_in, this.f11z.next_in_index, 1);
            zStream = this.f11z;
            zStream.next_in_index++;
            this.need--;
        }
        return r;
    }

    private void checksum(int n, long v) {
        for (int i = 0; i < n; i++) {
            this.crcbuf[i] = (byte) ((int) (255 & v));
            v >>= 8;
        }
        this.f11z.adler.update(this.crcbuf, 0, n);
    }

    public GZIPHeader getGZIPHeader() {
        return this.gheader;
    }

    boolean inParsingHeader() {
        switch (this.mode) {
            case 2:
            case 3:
            case 4:
            case 5:
            case 14:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
            case 22:
            case 23:
                return true;
            default:
                return false;
        }
    }
}
