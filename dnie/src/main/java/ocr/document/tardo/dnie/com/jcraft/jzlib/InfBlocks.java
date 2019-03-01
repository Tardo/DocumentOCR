package com.jcraft.jzlib;

import org.bouncycastle.asn1.eac.CertificateBody;

final class InfBlocks {
    private static final int BAD = 9;
    private static final int BTREE = 4;
    private static final int CODES = 6;
    private static final int DONE = 8;
    private static final int DRY = 7;
    private static final int DTREE = 5;
    private static final int LENS = 1;
    private static final int MANY = 1440;
    private static final int STORED = 2;
    private static final int TABLE = 3;
    private static final int TYPE = 0;
    private static final int Z_BUF_ERROR = -5;
    private static final int Z_DATA_ERROR = -3;
    private static final int Z_ERRNO = -1;
    private static final int Z_MEM_ERROR = -4;
    private static final int Z_NEED_DICT = 2;
    private static final int Z_OK = 0;
    private static final int Z_STREAM_END = 1;
    private static final int Z_STREAM_ERROR = -2;
    private static final int Z_VERSION_ERROR = -6;
    static final int[] border = new int[]{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    private static final int[] inflate_mask = new int[]{0, 1, 3, 7, 15, 31, 63, CertificateBody.profileType, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535};
    int[] bb = new int[1];
    int[] bd = new int[1];
    int bitb;
    int bitk;
    int[] bl = new int[1];
    int[] blens;
    private boolean check;
    private final InfCodes codes;
    int end;
    int[] hufts;
    int index;
    private final InfTree inftree = new InfTree();
    int last;
    int left;
    int mode;
    int read;
    int table;
    int[] tb = new int[1];
    int[][] td = new int[1][];
    int[] tdi = new int[1];
    int[][] tl = new int[1][];
    int[] tli = new int[1];
    byte[] window;
    int write;
    /* renamed from: z */
    private final ZStream f2z;

    InfBlocks(ZStream z, int w) {
        boolean z2 = true;
        this.f2z = z;
        this.codes = new InfCodes(this.f2z, this);
        this.hufts = new int[4320];
        this.window = new byte[w];
        this.end = w;
        if (z.istate.wrap == 0) {
            z2 = false;
        }
        this.check = z2;
        this.mode = 0;
        reset();
    }

    void reset() {
        if (this.mode == 4 || this.mode == 5) {
        }
        if (this.mode == 6) {
            this.codes.free(this.f2z);
        }
        this.mode = 0;
        this.bitk = 0;
        this.bitb = 0;
        this.write = 0;
        this.read = 0;
        if (this.check) {
            this.f2z.adler.reset();
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    int proc(int r27) {
        /*
        r26 = this;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r4.next_in_index;
        r22 = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r4.avail_in;
        r21 = r0;
        r0 = r26;
        r14 = r0.bitb;
        r0 = r26;
        r0 = r0.bitk;
        r19 = r0;
        r0 = r26;
        r0 = r0.write;
        r24 = r0;
        r0 = r26;
        r4 = r0.read;
        r0 = r24;
        if (r0 >= r4) goto L_0x0070;
    L_0x0028:
        r0 = r26;
        r4 = r0.read;
        r4 = r4 - r24;
        r20 = r4 + -1;
    L_0x0030:
        r0 = r26;
        r4 = r0.mode;
        switch(r4) {
            case 0: goto L_0x09f0;
            case 1: goto L_0x09ec;
            case 2: goto L_0x0265;
            case 3: goto L_0x09e8;
            case 4: goto L_0x048e;
            case 5: goto L_0x05bf;
            case 6: goto L_0x0864;
            case 7: goto L_0x0901;
            case 8: goto L_0x0970;
            case 9: goto L_0x09aa;
            default: goto L_0x0037;
        };
    L_0x0037:
        r27 = -2;
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r22 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r22;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
    L_0x006f:
        return r4;
    L_0x0070:
        r0 = r26;
        r4 = r0.end;
        r20 = r4 - r24;
        goto L_0x0030;
    L_0x0077:
        r4 = 3;
        r0 = r19;
        if (r0 >= r4) goto L_0x00cf;
    L_0x007c:
        if (r21 == 0) goto L_0x0096;
    L_0x007e:
        r27 = 0;
        r21 = r21 + -1;
        r0 = r26;
        r4 = r0.f2z;
        r4 = r4.next_in;
        r22 = r23 + 1;
        r4 = r4[r23];
        r4 = r4 & 255;
        r4 = r4 << r19;
        r14 = r14 | r4;
        r19 = r19 + 8;
        r23 = r22;
        goto L_0x0077;
    L_0x0096:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r23 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r23;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        r22 = r23;
        goto L_0x006f;
    L_0x00cf:
        r25 = r14 & 7;
        r4 = r25 & 1;
        r0 = r26;
        r0.last = r4;
        r4 = r25 >>> 1;
        switch(r4) {
            case 0: goto L_0x00e0;
            case 1: goto L_0x00f0;
            case 2: goto L_0x0136;
            case 3: goto L_0x0140;
            default: goto L_0x00dc;
        };
    L_0x00dc:
        r22 = r23;
        goto L_0x0030;
    L_0x00e0:
        r14 = r14 >>> 3;
        r19 = r19 + -3;
        r25 = r19 & 7;
        r14 = r14 >>> r25;
        r19 = r19 - r25;
        r4 = 1;
        r0 = r26;
        r0.mode = r4;
        goto L_0x00dc;
    L_0x00f0:
        r0 = r26;
        r4 = r0.bl;
        r0 = r26;
        r5 = r0.bd;
        r0 = r26;
        r6 = r0.tl;
        r0 = r26;
        r7 = r0.td;
        r0 = r26;
        r8 = r0.f2z;
        com.jcraft.jzlib.InfTree.inflate_trees_fixed(r4, r5, r6, r7, r8);
        r0 = r26;
        r4 = r0.codes;
        r0 = r26;
        r5 = r0.bl;
        r6 = 0;
        r5 = r5[r6];
        r0 = r26;
        r6 = r0.bd;
        r7 = 0;
        r6 = r6[r7];
        r0 = r26;
        r7 = r0.tl;
        r8 = 0;
        r7 = r7[r8];
        r8 = 0;
        r0 = r26;
        r9 = r0.td;
        r10 = 0;
        r9 = r9[r10];
        r10 = 0;
        r4.init(r5, r6, r7, r8, r9, r10);
        r14 = r14 >>> 3;
        r19 = r19 + -3;
        r4 = 6;
        r0 = r26;
        r0.mode = r4;
        goto L_0x00dc;
    L_0x0136:
        r14 = r14 >>> 3;
        r19 = r19 + -3;
        r4 = 3;
        r0 = r26;
        r0.mode = r4;
        goto L_0x00dc;
    L_0x0140:
        r14 = r14 >>> 3;
        r19 = r19 + -3;
        r4 = 9;
        r0 = r26;
        r0.mode = r4;
        r0 = r26;
        r4 = r0.f2z;
        r5 = "invalid block type";
        r4.msg = r5;
        r27 = -3;
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r23 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r23;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        r22 = r23;
        goto L_0x006f;
    L_0x018e:
        r4 = 32;
        r0 = r19;
        if (r0 >= r4) goto L_0x01e8;
    L_0x0194:
        if (r21 == 0) goto L_0x01ae;
    L_0x0196:
        r27 = 0;
        r21 = r21 + -1;
        r0 = r26;
        r4 = r0.f2z;
        r4 = r4.next_in;
        r22 = r23 + 1;
        r4 = r4[r23];
        r4 = r4 & 255;
        r4 = r4 << r19;
        r14 = r14 | r4;
        r19 = r19 + 8;
        r23 = r22;
        goto L_0x018e;
    L_0x01ae:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r23 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r23;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        r22 = r23;
        goto L_0x006f;
    L_0x01e8:
        r4 = r14 ^ -1;
        r4 = r4 >>> 16;
        r5 = 65535; // 0xffff float:9.1834E-41 double:3.23786E-319;
        r4 = r4 & r5;
        r5 = 65535; // 0xffff float:9.1834E-41 double:3.23786E-319;
        r5 = r5 & r14;
        if (r4 == r5) goto L_0x0240;
    L_0x01f6:
        r4 = 9;
        r0 = r26;
        r0.mode = r4;
        r0 = r26;
        r4 = r0.f2z;
        r5 = "invalid stored block lengths";
        r4.msg = r5;
        r27 = -3;
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r23 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r23;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        r22 = r23;
        goto L_0x006f;
    L_0x0240:
        r4 = 65535; // 0xffff float:9.1834E-41 double:3.23786E-319;
        r4 = r4 & r14;
        r0 = r26;
        r0.left = r4;
        r19 = 0;
        r14 = r19;
        r0 = r26;
        r4 = r0.left;
        if (r4 == 0) goto L_0x025b;
    L_0x0252:
        r4 = 2;
    L_0x0253:
        r0 = r26;
        r0.mode = r4;
        r22 = r23;
        goto L_0x0030;
    L_0x025b:
        r0 = r26;
        r4 = r0.last;
        if (r4 == 0) goto L_0x0263;
    L_0x0261:
        r4 = 7;
        goto L_0x0253;
    L_0x0263:
        r4 = 0;
        goto L_0x0253;
    L_0x0265:
        if (r21 != 0) goto L_0x029f;
    L_0x0267:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r22 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r22;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        goto L_0x006f;
    L_0x029f:
        if (r20 != 0) goto L_0x0353;
    L_0x02a1:
        r0 = r26;
        r4 = r0.end;
        r0 = r24;
        if (r0 != r4) goto L_0x02c1;
    L_0x02a9:
        r0 = r26;
        r4 = r0.read;
        if (r4 == 0) goto L_0x02c1;
    L_0x02af:
        r24 = 0;
        r0 = r26;
        r4 = r0.read;
        r0 = r24;
        if (r0 >= r4) goto L_0x033d;
    L_0x02b9:
        r0 = r26;
        r4 = r0.read;
        r4 = r4 - r24;
        r20 = r4 + -1;
    L_0x02c1:
        if (r20 != 0) goto L_0x0353;
    L_0x02c3:
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r27 = r26.inflate_flush(r27);
        r0 = r26;
        r0 = r0.write;
        r24 = r0;
        r0 = r26;
        r4 = r0.read;
        r0 = r24;
        if (r0 >= r4) goto L_0x0345;
    L_0x02db:
        r0 = r26;
        r4 = r0.read;
        r4 = r4 - r24;
        r20 = r4 + -1;
    L_0x02e3:
        r0 = r26;
        r4 = r0.end;
        r0 = r24;
        if (r0 != r4) goto L_0x0303;
    L_0x02eb:
        r0 = r26;
        r4 = r0.read;
        if (r4 == 0) goto L_0x0303;
    L_0x02f1:
        r24 = 0;
        r0 = r26;
        r4 = r0.read;
        r0 = r24;
        if (r0 >= r4) goto L_0x034c;
    L_0x02fb:
        r0 = r26;
        r4 = r0.read;
        r4 = r4 - r24;
        r20 = r4 + -1;
    L_0x0303:
        if (r20 != 0) goto L_0x0353;
    L_0x0305:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r22 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r22;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        goto L_0x006f;
    L_0x033d:
        r0 = r26;
        r4 = r0.end;
        r20 = r4 - r24;
        goto L_0x02c1;
    L_0x0345:
        r0 = r26;
        r4 = r0.end;
        r20 = r4 - r24;
        goto L_0x02e3;
    L_0x034c:
        r0 = r26;
        r4 = r0.end;
        r20 = r4 - r24;
        goto L_0x0303;
    L_0x0353:
        r27 = 0;
        r0 = r26;
        r0 = r0.left;
        r25 = r0;
        r0 = r25;
        r1 = r21;
        if (r0 <= r1) goto L_0x0363;
    L_0x0361:
        r25 = r21;
    L_0x0363:
        r0 = r25;
        r1 = r20;
        if (r0 <= r1) goto L_0x036b;
    L_0x0369:
        r25 = r20;
    L_0x036b:
        r0 = r26;
        r4 = r0.f2z;
        r4 = r4.next_in;
        r0 = r26;
        r5 = r0.window;
        r0 = r22;
        r1 = r24;
        r2 = r25;
        java.lang.System.arraycopy(r4, r0, r5, r1, r2);
        r22 = r22 + r25;
        r21 = r21 - r25;
        r24 = r24 + r25;
        r20 = r20 - r25;
        r0 = r26;
        r4 = r0.left;
        r4 = r4 - r25;
        r0 = r26;
        r0.left = r4;
        if (r4 != 0) goto L_0x0030;
    L_0x0392:
        r0 = r26;
        r4 = r0.last;
        if (r4 == 0) goto L_0x039f;
    L_0x0398:
        r4 = 7;
    L_0x0399:
        r0 = r26;
        r0.mode = r4;
        goto L_0x0030;
    L_0x039f:
        r4 = 0;
        goto L_0x0399;
    L_0x03a1:
        r4 = 14;
        r0 = r19;
        if (r0 >= r4) goto L_0x03fb;
    L_0x03a7:
        if (r21 == 0) goto L_0x03c1;
    L_0x03a9:
        r27 = 0;
        r21 = r21 + -1;
        r0 = r26;
        r4 = r0.f2z;
        r4 = r4.next_in;
        r22 = r23 + 1;
        r4 = r4[r23];
        r4 = r4 & 255;
        r4 = r4 << r19;
        r14 = r14 | r4;
        r19 = r19 + 8;
        r23 = r22;
        goto L_0x03a1;
    L_0x03c1:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r23 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r23;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        r22 = r23;
        goto L_0x006f;
    L_0x03fb:
        r0 = r14 & 16383;
        r25 = r0;
        r0 = r25;
        r1 = r26;
        r1.table = r0;
        r4 = r25 & 31;
        r5 = 29;
        if (r4 > r5) goto L_0x0413;
    L_0x040b:
        r4 = r25 >> 5;
        r4 = r4 & 31;
        r5 = 29;
        if (r4 <= r5) goto L_0x045d;
    L_0x0413:
        r4 = 9;
        r0 = r26;
        r0.mode = r4;
        r0 = r26;
        r4 = r0.f2z;
        r5 = "too many length or distance symbols";
        r4.msg = r5;
        r27 = -3;
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r23 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r23;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        r22 = r23;
        goto L_0x006f;
    L_0x045d:
        r4 = r25 & 31;
        r4 = r4 + 258;
        r5 = r25 >> 5;
        r5 = r5 & 31;
        r25 = r4 + r5;
        r0 = r26;
        r4 = r0.blens;
        if (r4 == 0) goto L_0x0476;
    L_0x046d:
        r0 = r26;
        r4 = r0.blens;
        r4 = r4.length;
        r0 = r25;
        if (r4 >= r0) goto L_0x04bd;
    L_0x0476:
        r0 = r25;
        r4 = new int[r0];
        r0 = r26;
        r0.blens = r4;
    L_0x047e:
        r14 = r14 >>> 14;
        r19 = r19 + -14;
        r4 = 0;
        r0 = r26;
        r0.index = r4;
        r4 = 4;
        r0 = r26;
        r0.mode = r4;
        r22 = r23;
    L_0x048e:
        r0 = r26;
        r4 = r0.index;
        r0 = r26;
        r5 = r0.table;
        r5 = r5 >>> 10;
        r5 = r5 + 4;
        if (r4 >= r5) goto L_0x0527;
    L_0x049c:
        r23 = r22;
    L_0x049e:
        r4 = 3;
        r0 = r19;
        if (r0 >= r4) goto L_0x0509;
    L_0x04a3:
        if (r21 == 0) goto L_0x04cf;
    L_0x04a5:
        r27 = 0;
        r21 = r21 + -1;
        r0 = r26;
        r4 = r0.f2z;
        r4 = r4.next_in;
        r22 = r23 + 1;
        r4 = r4[r23];
        r4 = r4 & 255;
        r4 = r4 << r19;
        r14 = r14 | r4;
        r19 = r19 + 8;
        r23 = r22;
        goto L_0x049e;
    L_0x04bd:
        r16 = 0;
    L_0x04bf:
        r0 = r16;
        r1 = r25;
        if (r0 >= r1) goto L_0x047e;
    L_0x04c5:
        r0 = r26;
        r4 = r0.blens;
        r5 = 0;
        r4[r16] = r5;
        r16 = r16 + 1;
        goto L_0x04bf;
    L_0x04cf:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r23 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r23;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        r22 = r23;
        goto L_0x006f;
    L_0x0509:
        r0 = r26;
        r4 = r0.blens;
        r5 = border;
        r0 = r26;
        r6 = r0.index;
        r7 = r6 + 1;
        r0 = r26;
        r0.index = r7;
        r5 = r5[r6];
        r6 = r14 & 7;
        r4[r5] = r6;
        r14 = r14 >>> 3;
        r19 = r19 + -3;
        r22 = r23;
        goto L_0x048e;
    L_0x0527:
        r0 = r26;
        r4 = r0.index;
        r5 = 19;
        if (r4 >= r5) goto L_0x0545;
    L_0x052f:
        r0 = r26;
        r4 = r0.blens;
        r5 = border;
        r0 = r26;
        r6 = r0.index;
        r7 = r6 + 1;
        r0 = r26;
        r0.index = r7;
        r5 = r5[r6];
        r6 = 0;
        r4[r5] = r6;
        goto L_0x0527;
    L_0x0545:
        r0 = r26;
        r4 = r0.bb;
        r5 = 0;
        r6 = 7;
        r4[r5] = r6;
        r0 = r26;
        r4 = r0.inftree;
        r0 = r26;
        r5 = r0.blens;
        r0 = r26;
        r6 = r0.bb;
        r0 = r26;
        r7 = r0.tb;
        r0 = r26;
        r8 = r0.hufts;
        r0 = r26;
        r9 = r0.f2z;
        r25 = r4.inflate_trees_bits(r5, r6, r7, r8, r9);
        if (r25 == 0) goto L_0x05b5;
    L_0x056b:
        r27 = r25;
        r4 = -3;
        r0 = r27;
        if (r0 != r4) goto L_0x057d;
    L_0x0572:
        r4 = 0;
        r0 = r26;
        r0.blens = r4;
        r4 = 9;
        r0 = r26;
        r0.mode = r4;
    L_0x057d:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r22 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r22;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        goto L_0x006f;
    L_0x05b5:
        r4 = 0;
        r0 = r26;
        r0.index = r4;
        r4 = 5;
        r0 = r26;
        r0.mode = r4;
    L_0x05bf:
        r0 = r26;
        r0 = r0.table;
        r25 = r0;
        r0 = r26;
        r4 = r0.index;
        r5 = r25 & 31;
        r5 = r5 + 258;
        r6 = r25 >> 5;
        r6 = r6 & 31;
        r5 = r5 + r6;
        if (r4 < r5) goto L_0x066d;
    L_0x05d4:
        r0 = r26;
        r4 = r0.tb;
        r5 = 0;
        r6 = -1;
        r4[r5] = r6;
        r0 = r26;
        r4 = r0.bl;
        r5 = 0;
        r6 = 9;
        r4[r5] = r6;
        r0 = r26;
        r4 = r0.bd;
        r5 = 0;
        r6 = 6;
        r4[r5] = r6;
        r0 = r26;
        r0 = r0.table;
        r25 = r0;
        r0 = r26;
        r4 = r0.inftree;
        r5 = r25 & 31;
        r5 = r5 + 257;
        r6 = r25 >> 5;
        r6 = r6 & 31;
        r6 = r6 + 1;
        r0 = r26;
        r7 = r0.blens;
        r0 = r26;
        r8 = r0.bl;
        r0 = r26;
        r9 = r0.bd;
        r0 = r26;
        r10 = r0.tli;
        r0 = r26;
        r11 = r0.tdi;
        r0 = r26;
        r12 = r0.hufts;
        r0 = r26;
        r13 = r0.f2z;
        r25 = r4.inflate_trees_dynamic(r5, r6, r7, r8, r9, r10, r11, r12, r13);
        if (r25 == 0) goto L_0x0834;
    L_0x0623:
        r4 = -3;
        r0 = r25;
        if (r0 != r4) goto L_0x0633;
    L_0x0628:
        r4 = 0;
        r0 = r26;
        r0.blens = r4;
        r4 = 9;
        r0 = r26;
        r0.mode = r4;
    L_0x0633:
        r27 = r25;
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r22 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r22;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        goto L_0x006f;
    L_0x066d:
        r0 = r26;
        r4 = r0.bb;
        r5 = 0;
        r25 = r4[r5];
        r23 = r22;
    L_0x0676:
        r0 = r19;
        r1 = r25;
        if (r0 >= r1) goto L_0x06d0;
    L_0x067c:
        if (r21 == 0) goto L_0x0696;
    L_0x067e:
        r27 = 0;
        r21 = r21 + -1;
        r0 = r26;
        r4 = r0.f2z;
        r4 = r4.next_in;
        r22 = r23 + 1;
        r4 = r4[r23];
        r4 = r4 & 255;
        r4 = r4 << r19;
        r14 = r14 | r4;
        r19 = r19 + 8;
        r23 = r22;
        goto L_0x0676;
    L_0x0696:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r23 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r23;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        r22 = r23;
        goto L_0x006f;
    L_0x06d0:
        r0 = r26;
        r4 = r0.tb;
        r5 = 0;
        r4 = r4[r5];
        r5 = -1;
        if (r4 != r5) goto L_0x06da;
    L_0x06da:
        r0 = r26;
        r4 = r0.hufts;
        r0 = r26;
        r5 = r0.tb;
        r6 = 0;
        r5 = r5[r6];
        r6 = inflate_mask;
        r6 = r6[r25];
        r6 = r6 & r14;
        r5 = r5 + r6;
        r5 = r5 * 3;
        r5 = r5 + 1;
        r25 = r4[r5];
        r0 = r26;
        r4 = r0.hufts;
        r0 = r26;
        r5 = r0.tb;
        r6 = 0;
        r5 = r5[r6];
        r6 = inflate_mask;
        r6 = r6[r25];
        r6 = r6 & r14;
        r5 = r5 + r6;
        r5 = r5 * 3;
        r5 = r5 + 2;
        r15 = r4[r5];
        r4 = 16;
        if (r15 >= r4) goto L_0x0724;
    L_0x070c:
        r14 = r14 >>> r25;
        r19 = r19 - r25;
        r0 = r26;
        r4 = r0.blens;
        r0 = r26;
        r5 = r0.index;
        r6 = r5 + 1;
        r0 = r26;
        r0.index = r6;
        r4[r5] = r15;
        r22 = r23;
        goto L_0x05bf;
    L_0x0724:
        r4 = 18;
        if (r15 != r4) goto L_0x0750;
    L_0x0728:
        r16 = 7;
    L_0x072a:
        r4 = 18;
        if (r15 != r4) goto L_0x0753;
    L_0x072e:
        r18 = 11;
    L_0x0730:
        r4 = r25 + r16;
        r0 = r19;
        if (r0 >= r4) goto L_0x0790;
    L_0x0736:
        if (r21 == 0) goto L_0x0756;
    L_0x0738:
        r27 = 0;
        r21 = r21 + -1;
        r0 = r26;
        r4 = r0.f2z;
        r4 = r4.next_in;
        r22 = r23 + 1;
        r4 = r4[r23];
        r4 = r4 & 255;
        r4 = r4 << r19;
        r14 = r14 | r4;
        r19 = r19 + 8;
        r23 = r22;
        goto L_0x0730;
    L_0x0750:
        r16 = r15 + -14;
        goto L_0x072a;
    L_0x0753:
        r18 = 3;
        goto L_0x0730;
    L_0x0756:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r23 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r23;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        r22 = r23;
        goto L_0x006f;
    L_0x0790:
        r14 = r14 >>> r25;
        r19 = r19 - r25;
        r4 = inflate_mask;
        r4 = r4[r16];
        r4 = r4 & r14;
        r18 = r18 + r4;
        r14 = r14 >>> r16;
        r19 = r19 - r16;
        r0 = r26;
        r0 = r0.index;
        r16 = r0;
        r0 = r26;
        r0 = r0.table;
        r25 = r0;
        r4 = r16 + r18;
        r5 = r25 & 31;
        r5 = r5 + 258;
        r6 = r25 >> 5;
        r6 = r6 & 31;
        r5 = r5 + r6;
        if (r4 > r5) goto L_0x07c1;
    L_0x07b8:
        r4 = 16;
        if (r15 != r4) goto L_0x0810;
    L_0x07bc:
        r4 = 1;
        r0 = r16;
        if (r0 >= r4) goto L_0x0810;
    L_0x07c1:
        r4 = 0;
        r0 = r26;
        r0.blens = r4;
        r4 = 9;
        r0 = r26;
        r0.mode = r4;
        r0 = r26;
        r4 = r0.f2z;
        r5 = "invalid bit length repeat";
        r4.msg = r5;
        r27 = -3;
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r23 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r23;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        r22 = r23;
        goto L_0x006f;
    L_0x0810:
        r4 = 16;
        if (r15 != r4) goto L_0x0832;
    L_0x0814:
        r0 = r26;
        r4 = r0.blens;
        r5 = r16 + -1;
        r15 = r4[r5];
    L_0x081c:
        r0 = r26;
        r4 = r0.blens;
        r17 = r16 + 1;
        r4[r16] = r15;
        r18 = r18 + -1;
        if (r18 != 0) goto L_0x09e4;
    L_0x0828:
        r0 = r17;
        r1 = r26;
        r1.index = r0;
        r22 = r23;
        goto L_0x05bf;
    L_0x0832:
        r15 = 0;
        goto L_0x081c;
    L_0x0834:
        r0 = r26;
        r4 = r0.codes;
        r0 = r26;
        r5 = r0.bl;
        r6 = 0;
        r5 = r5[r6];
        r0 = r26;
        r6 = r0.bd;
        r7 = 0;
        r6 = r6[r7];
        r0 = r26;
        r7 = r0.hufts;
        r0 = r26;
        r8 = r0.tli;
        r9 = 0;
        r8 = r8[r9];
        r0 = r26;
        r9 = r0.hufts;
        r0 = r26;
        r10 = r0.tdi;
        r11 = 0;
        r10 = r10[r11];
        r4.init(r5, r6, r7, r8, r9, r10);
        r4 = 6;
        r0 = r26;
        r0.mode = r4;
    L_0x0864:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r22 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r22;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r0 = r26;
        r4 = r0.codes;
        r0 = r27;
        r27 = r4.proc(r0);
        r4 = 1;
        r0 = r27;
        if (r0 == r4) goto L_0x08ab;
    L_0x08a5:
        r4 = r26.inflate_flush(r27);
        goto L_0x006f;
    L_0x08ab:
        r27 = 0;
        r0 = r26;
        r4 = r0.codes;
        r0 = r26;
        r5 = r0.f2z;
        r4.free(r5);
        r0 = r26;
        r4 = r0.f2z;
        r0 = r4.next_in_index;
        r22 = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r4.avail_in;
        r21 = r0;
        r0 = r26;
        r14 = r0.bitb;
        r0 = r26;
        r0 = r0.bitk;
        r19 = r0;
        r0 = r26;
        r0 = r0.write;
        r24 = r0;
        r0 = r26;
        r4 = r0.read;
        r0 = r24;
        if (r0 >= r4) goto L_0x08f5;
    L_0x08e0:
        r0 = r26;
        r4 = r0.read;
        r4 = r4 - r24;
        r20 = r4 + -1;
    L_0x08e8:
        r0 = r26;
        r4 = r0.last;
        if (r4 != 0) goto L_0x08fc;
    L_0x08ee:
        r4 = 0;
        r0 = r26;
        r0.mode = r4;
        goto L_0x0030;
    L_0x08f5:
        r0 = r26;
        r4 = r0.end;
        r20 = r4 - r24;
        goto L_0x08e8;
    L_0x08fc:
        r4 = 7;
        r0 = r26;
        r0.mode = r4;
    L_0x0901:
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r27 = r26.inflate_flush(r27);
        r0 = r26;
        r0 = r0.write;
        r24 = r0;
        r0 = r26;
        r4 = r0.read;
        r0 = r24;
        if (r0 >= r4) goto L_0x0963;
    L_0x0919:
        r0 = r26;
        r4 = r0.read;
        r4 = r4 - r24;
        r20 = r4 + -1;
    L_0x0921:
        r0 = r26;
        r4 = r0.read;
        r0 = r26;
        r5 = r0.write;
        if (r4 == r5) goto L_0x096a;
    L_0x092b:
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r22 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r22;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        goto L_0x006f;
    L_0x0963:
        r0 = r26;
        r4 = r0.end;
        r20 = r4 - r24;
        goto L_0x0921;
    L_0x096a:
        r4 = 8;
        r0 = r26;
        r0.mode = r4;
    L_0x0970:
        r27 = 1;
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r22 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r22;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        goto L_0x006f;
    L_0x09aa:
        r27 = -3;
        r0 = r26;
        r0.bitb = r14;
        r0 = r19;
        r1 = r26;
        r1.bitk = r0;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r21;
        r4.avail_in = r0;
        r0 = r26;
        r4 = r0.f2z;
        r6 = r4.total_in;
        r0 = r26;
        r5 = r0.f2z;
        r5 = r5.next_in_index;
        r5 = r22 - r5;
        r8 = (long) r5;
        r6 = r6 + r8;
        r4.total_in = r6;
        r0 = r26;
        r4 = r0.f2z;
        r0 = r22;
        r4.next_in_index = r0;
        r0 = r24;
        r1 = r26;
        r1.write = r0;
        r4 = r26.inflate_flush(r27);
        goto L_0x006f;
    L_0x09e4:
        r16 = r17;
        goto L_0x081c;
    L_0x09e8:
        r23 = r22;
        goto L_0x03a1;
    L_0x09ec:
        r23 = r22;
        goto L_0x018e;
    L_0x09f0:
        r23 = r22;
        goto L_0x0077;
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jcraft.jzlib.InfBlocks.proc(int):int");
    }

    void free() {
        reset();
        this.window = null;
        this.hufts = null;
    }

    void set_dictionary(byte[] d, int start, int n) {
        System.arraycopy(d, start, this.window, 0, n);
        this.write = n;
        this.read = n;
    }

    int sync_point() {
        return this.mode == 1 ? 1 : 0;
    }

    int inflate_flush(int r) {
        int p = this.f2z.next_out_index;
        int q = this.read;
        int n = (q <= this.write ? this.write : this.end) - q;
        if (n > this.f2z.avail_out) {
            n = this.f2z.avail_out;
        }
        if (n != 0 && r == -5) {
            r = 0;
        }
        ZStream zStream = this.f2z;
        zStream.avail_out -= n;
        zStream = this.f2z;
        zStream.total_out += (long) n;
        if (this.check && n > 0) {
            this.f2z.adler.update(this.window, q, n);
        }
        System.arraycopy(this.window, q, this.f2z.next_out, p, n);
        p += n;
        q += n;
        if (q == this.end) {
            if (this.write == this.end) {
                this.write = 0;
            }
            n = this.write - 0;
            if (n > this.f2z.avail_out) {
                n = this.f2z.avail_out;
            }
            if (n != 0 && r == -5) {
                r = 0;
            }
            zStream = this.f2z;
            zStream.avail_out -= n;
            zStream = this.f2z;
            zStream.total_out += (long) n;
            if (this.check && n > 0) {
                this.f2z.adler.update(this.window, 0, n);
            }
            System.arraycopy(this.window, 0, this.f2z.next_out, p, n);
            p += n;
            q = 0 + n;
        }
        this.f2z.next_out_index = p;
        this.read = q;
        return r;
    }
}
