package com.jcraft.jzlib;

import org.bouncycastle.asn1.eac.CertificateBody;

final class InfCodes {
    private static final int BADCODE = 9;
    private static final int COPY = 5;
    private static final int DIST = 3;
    private static final int DISTEXT = 4;
    private static final int END = 8;
    private static final int LEN = 1;
    private static final int LENEXT = 2;
    private static final int LIT = 6;
    private static final int START = 0;
    private static final int WASH = 7;
    private static final int Z_BUF_ERROR = -5;
    private static final int Z_DATA_ERROR = -3;
    private static final int Z_ERRNO = -1;
    private static final int Z_MEM_ERROR = -4;
    private static final int Z_NEED_DICT = 2;
    private static final int Z_OK = 0;
    private static final int Z_STREAM_END = 1;
    private static final int Z_STREAM_ERROR = -2;
    private static final int Z_VERSION_ERROR = -6;
    private static final int[] inflate_mask = new int[]{0, 1, 3, 7, 15, 31, 63, CertificateBody.profileType, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535};
    byte dbits;
    int dist;
    int[] dtree;
    int dtree_index;
    int get;
    byte lbits;
    int len;
    int lit;
    int[] ltree;
    int ltree_index;
    int mode;
    int need;
    /* renamed from: s */
    private final InfBlocks f3s;
    int[] tree;
    int tree_index = 0;
    /* renamed from: z */
    private final ZStream f4z;

    InfCodes(ZStream z, InfBlocks s) {
        this.f4z = z;
        this.f3s = s;
    }

    void init(int bl, int bd, int[] tl, int tl_index, int[] td, int td_index) {
        this.mode = 0;
        this.lbits = (byte) bl;
        this.dbits = (byte) bd;
        this.ltree = tl;
        this.ltree_index = tl_index;
        this.dtree = td;
        this.dtree_index = td_index;
        this.tree = null;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    int proc(int r25) {
        /*
        r24 = this;
        r11 = 0;
        r16 = 0;
        r19 = 0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r2.next_in_index;
        r19 = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r2.avail_in;
        r18 = r0;
        r0 = r24;
        r2 = r0.f3s;
        r11 = r2.bitb;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r2.bitk;
        r16 = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r2.write;
        r21 = r0;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r0 = r21;
        if (r0 >= r2) goto L_0x008b;
    L_0x0035:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r2 = r2 - r21;
        r17 = r2 + -1;
    L_0x003f:
        r0 = r24;
        r2 = r0.mode;
        switch(r2) {
            case 0: goto L_0x0094;
            case 1: goto L_0x016f;
            case 2: goto L_0x02b2;
            case 3: goto L_0x034c;
            case 4: goto L_0x046b;
            case 5: goto L_0x04ed;
            case 6: goto L_0x0619;
            case 7: goto L_0x0719;
            case 8: goto L_0x07b3;
            case 9: goto L_0x07f9;
            default: goto L_0x0046;
        };
    L_0x0046:
        r25 = -2;
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r19 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r19;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
    L_0x008a:
        return r2;
    L_0x008b:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r17 = r2 - r21;
        goto L_0x003f;
    L_0x0094:
        r2 = 258; // 0x102 float:3.62E-43 double:1.275E-321;
        r0 = r17;
        if (r0 < r2) goto L_0x0152;
    L_0x009a:
        r2 = 10;
        r0 = r18;
        if (r0 < r2) goto L_0x0152;
    L_0x00a0:
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r19 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r19;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r3 = r0.lbits;
        r0 = r24;
        r4 = r0.dbits;
        r0 = r24;
        r5 = r0.ltree;
        r0 = r24;
        r6 = r0.ltree_index;
        r0 = r24;
        r7 = r0.dtree;
        r0 = r24;
        r8 = r0.dtree_index;
        r0 = r24;
        r9 = r0.f3s;
        r0 = r24;
        r10 = r0.f4z;
        r2 = r24;
        r25 = r2.inflate_fast(r3, r4, r5, r6, r7, r8, r9, r10);
        r0 = r24;
        r2 = r0.f4z;
        r0 = r2.next_in_index;
        r19 = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r2.avail_in;
        r18 = r0;
        r0 = r24;
        r2 = r0.f3s;
        r11 = r2.bitb;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r2.bitk;
        r16 = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r2.write;
        r21 = r0;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r0 = r21;
        if (r0 >= r2) goto L_0x0146;
    L_0x012e:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r2 = r2 - r21;
        r17 = r2 + -1;
    L_0x0138:
        if (r25 == 0) goto L_0x0152;
    L_0x013a:
        r2 = 1;
        r0 = r25;
        if (r0 != r2) goto L_0x014f;
    L_0x013f:
        r2 = 7;
    L_0x0140:
        r0 = r24;
        r0.mode = r2;
        goto L_0x003f;
    L_0x0146:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r17 = r2 - r21;
        goto L_0x0138;
    L_0x014f:
        r2 = 9;
        goto L_0x0140;
    L_0x0152:
        r0 = r24;
        r2 = r0.lbits;
        r0 = r24;
        r0.need = r2;
        r0 = r24;
        r2 = r0.ltree;
        r0 = r24;
        r0.tree = r2;
        r0 = r24;
        r2 = r0.ltree_index;
        r0 = r24;
        r0.tree_index = r2;
        r2 = 1;
        r0 = r24;
        r0.mode = r2;
    L_0x016f:
        r0 = r24;
        r15 = r0.need;
        r20 = r19;
    L_0x0175:
        r0 = r16;
        if (r0 >= r15) goto L_0x01d9;
    L_0x0179:
        if (r18 == 0) goto L_0x0193;
    L_0x017b:
        r25 = 0;
        r18 = r18 + -1;
        r0 = r24;
        r2 = r0.f4z;
        r2 = r2.next_in;
        r19 = r20 + 1;
        r2 = r2[r20];
        r2 = r2 & 255;
        r2 = r2 << r16;
        r11 = r11 | r2;
        r16 = r16 + 8;
        r20 = r19;
        goto L_0x0175;
    L_0x0193:
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r20 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r20;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        r19 = r20;
        goto L_0x008a;
    L_0x01d9:
        r0 = r24;
        r2 = r0.tree_index;
        r3 = inflate_mask;
        r3 = r3[r15];
        r3 = r3 & r11;
        r2 = r2 + r3;
        r23 = r2 * 3;
        r0 = r24;
        r2 = r0.tree;
        r3 = r23 + 1;
        r2 = r2[r3];
        r11 = r11 >>> r2;
        r0 = r24;
        r2 = r0.tree;
        r3 = r23 + 1;
        r2 = r2[r3];
        r16 = r16 - r2;
        r0 = r24;
        r2 = r0.tree;
        r12 = r2[r23];
        if (r12 != 0) goto L_0x0215;
    L_0x0200:
        r0 = r24;
        r2 = r0.tree;
        r3 = r23 + 2;
        r2 = r2[r3];
        r0 = r24;
        r0.lit = r2;
        r2 = 6;
        r0 = r24;
        r0.mode = r2;
        r19 = r20;
        goto L_0x003f;
    L_0x0215:
        r2 = r12 & 16;
        if (r2 == 0) goto L_0x0234;
    L_0x0219:
        r2 = r12 & 15;
        r0 = r24;
        r0.get = r2;
        r0 = r24;
        r2 = r0.tree;
        r3 = r23 + 2;
        r2 = r2[r3];
        r0 = r24;
        r0.len = r2;
        r2 = 2;
        r0 = r24;
        r0.mode = r2;
        r19 = r20;
        goto L_0x003f;
    L_0x0234:
        r2 = r12 & 64;
        if (r2 != 0) goto L_0x024f;
    L_0x0238:
        r0 = r24;
        r0.need = r12;
        r2 = r23 / 3;
        r0 = r24;
        r3 = r0.tree;
        r4 = r23 + 2;
        r3 = r3[r4];
        r2 = r2 + r3;
        r0 = r24;
        r0.tree_index = r2;
        r19 = r20;
        goto L_0x003f;
    L_0x024f:
        r2 = r12 & 32;
        if (r2 == 0) goto L_0x025c;
    L_0x0253:
        r2 = 7;
        r0 = r24;
        r0.mode = r2;
        r19 = r20;
        goto L_0x003f;
    L_0x025c:
        r2 = 9;
        r0 = r24;
        r0.mode = r2;
        r0 = r24;
        r2 = r0.f4z;
        r3 = "invalid literal/length code";
        r2.msg = r3;
        r25 = -3;
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r20 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r20;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        r19 = r20;
        goto L_0x008a;
    L_0x02b2:
        r0 = r24;
        r15 = r0.get;
        r20 = r19;
    L_0x02b8:
        r0 = r16;
        if (r0 >= r15) goto L_0x031c;
    L_0x02bc:
        if (r18 == 0) goto L_0x02d6;
    L_0x02be:
        r25 = 0;
        r18 = r18 + -1;
        r0 = r24;
        r2 = r0.f4z;
        r2 = r2.next_in;
        r19 = r20 + 1;
        r2 = r2[r20];
        r2 = r2 & 255;
        r2 = r2 << r16;
        r11 = r11 | r2;
        r16 = r16 + 8;
        r20 = r19;
        goto L_0x02b8;
    L_0x02d6:
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r20 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r20;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        r19 = r20;
        goto L_0x008a;
    L_0x031c:
        r0 = r24;
        r2 = r0.len;
        r3 = inflate_mask;
        r3 = r3[r15];
        r3 = r3 & r11;
        r2 = r2 + r3;
        r0 = r24;
        r0.len = r2;
        r11 = r11 >> r15;
        r16 = r16 - r15;
        r0 = r24;
        r2 = r0.dbits;
        r0 = r24;
        r0.need = r2;
        r0 = r24;
        r2 = r0.dtree;
        r0 = r24;
        r0.tree = r2;
        r0 = r24;
        r2 = r0.dtree_index;
        r0 = r24;
        r0.tree_index = r2;
        r2 = 3;
        r0 = r24;
        r0.mode = r2;
        r19 = r20;
    L_0x034c:
        r0 = r24;
        r15 = r0.need;
        r20 = r19;
    L_0x0352:
        r0 = r16;
        if (r0 >= r15) goto L_0x03b6;
    L_0x0356:
        if (r18 == 0) goto L_0x0370;
    L_0x0358:
        r25 = 0;
        r18 = r18 + -1;
        r0 = r24;
        r2 = r0.f4z;
        r2 = r2.next_in;
        r19 = r20 + 1;
        r2 = r2[r20];
        r2 = r2 & 255;
        r2 = r2 << r16;
        r11 = r11 | r2;
        r16 = r16 + 8;
        r20 = r19;
        goto L_0x0352;
    L_0x0370:
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r20 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r20;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        r19 = r20;
        goto L_0x008a;
    L_0x03b6:
        r0 = r24;
        r2 = r0.tree_index;
        r3 = inflate_mask;
        r3 = r3[r15];
        r3 = r3 & r11;
        r2 = r2 + r3;
        r23 = r2 * 3;
        r0 = r24;
        r2 = r0.tree;
        r3 = r23 + 1;
        r2 = r2[r3];
        r11 = r11 >> r2;
        r0 = r24;
        r2 = r0.tree;
        r3 = r23 + 1;
        r2 = r2[r3];
        r16 = r16 - r2;
        r0 = r24;
        r2 = r0.tree;
        r12 = r2[r23];
        r2 = r12 & 16;
        if (r2 == 0) goto L_0x03fa;
    L_0x03df:
        r2 = r12 & 15;
        r0 = r24;
        r0.get = r2;
        r0 = r24;
        r2 = r0.tree;
        r3 = r23 + 2;
        r2 = r2[r3];
        r0 = r24;
        r0.dist = r2;
        r2 = 4;
        r0 = r24;
        r0.mode = r2;
        r19 = r20;
        goto L_0x003f;
    L_0x03fa:
        r2 = r12 & 64;
        if (r2 != 0) goto L_0x0415;
    L_0x03fe:
        r0 = r24;
        r0.need = r12;
        r2 = r23 / 3;
        r0 = r24;
        r3 = r0.tree;
        r4 = r23 + 2;
        r3 = r3[r4];
        r2 = r2 + r3;
        r0 = r24;
        r0.tree_index = r2;
        r19 = r20;
        goto L_0x003f;
    L_0x0415:
        r2 = 9;
        r0 = r24;
        r0.mode = r2;
        r0 = r24;
        r2 = r0.f4z;
        r3 = "invalid distance code";
        r2.msg = r3;
        r25 = -3;
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r20 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r20;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        r19 = r20;
        goto L_0x008a;
    L_0x046b:
        r0 = r24;
        r15 = r0.get;
        r20 = r19;
    L_0x0471:
        r0 = r16;
        if (r0 >= r15) goto L_0x04d5;
    L_0x0475:
        if (r18 == 0) goto L_0x048f;
    L_0x0477:
        r25 = 0;
        r18 = r18 + -1;
        r0 = r24;
        r2 = r0.f4z;
        r2 = r2.next_in;
        r19 = r20 + 1;
        r2 = r2[r20];
        r2 = r2 & 255;
        r2 = r2 << r16;
        r11 = r11 | r2;
        r16 = r16 + 8;
        r20 = r19;
        goto L_0x0471;
    L_0x048f:
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r20 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r20;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        r19 = r20;
        goto L_0x008a;
    L_0x04d5:
        r0 = r24;
        r2 = r0.dist;
        r3 = inflate_mask;
        r3 = r3[r15];
        r3 = r3 & r11;
        r2 = r2 + r3;
        r0 = r24;
        r0.dist = r2;
        r11 = r11 >> r15;
        r16 = r16 - r15;
        r2 = 5;
        r0 = r24;
        r0.mode = r2;
        r19 = r20;
    L_0x04ed:
        r0 = r24;
        r2 = r0.dist;
        r13 = r21 - r2;
    L_0x04f3:
        if (r13 >= 0) goto L_0x0528;
    L_0x04f5:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r13 = r13 + r2;
        goto L_0x04f3;
    L_0x04fd:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.window;
        r22 = r21 + 1;
        r0 = r24;
        r3 = r0.f3s;
        r3 = r3.window;
        r14 = r13 + 1;
        r3 = r3[r13];
        r2[r21] = r3;
        r17 = r17 + -1;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        if (r14 != r2) goto L_0x083f;
    L_0x051b:
        r13 = 0;
    L_0x051c:
        r0 = r24;
        r2 = r0.len;
        r2 = r2 + -1;
        r0 = r24;
        r0.len = r2;
        r21 = r22;
    L_0x0528:
        r0 = r24;
        r2 = r0.len;
        if (r2 == 0) goto L_0x0612;
    L_0x052e:
        if (r17 != 0) goto L_0x04fd;
    L_0x0530:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r0 = r21;
        if (r0 != r2) goto L_0x0558;
    L_0x053a:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        if (r2 == 0) goto L_0x0558;
    L_0x0542:
        r21 = 0;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r0 = r21;
        if (r0 >= r2) goto L_0x05f6;
    L_0x054e:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r2 = r2 - r21;
        r17 = r2 + -1;
    L_0x0558:
        if (r17 != 0) goto L_0x04fd;
    L_0x055a:
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r25 = r2.inflate_flush(r0);
        r0 = r24;
        r2 = r0.f3s;
        r0 = r2.write;
        r21 = r0;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r0 = r21;
        if (r0 >= r2) goto L_0x0600;
    L_0x057e:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r2 = r2 - r21;
        r17 = r2 + -1;
    L_0x0588:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r0 = r21;
        if (r0 != r2) goto L_0x05b0;
    L_0x0592:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        if (r2 == 0) goto L_0x05b0;
    L_0x059a:
        r21 = 0;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r0 = r21;
        if (r0 >= r2) goto L_0x0609;
    L_0x05a6:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r2 = r2 - r21;
        r17 = r2 + -1;
    L_0x05b0:
        if (r17 != 0) goto L_0x04fd;
    L_0x05b2:
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r19 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r19;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        goto L_0x008a;
    L_0x05f6:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r17 = r2 - r21;
        goto L_0x0558;
    L_0x0600:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r17 = r2 - r21;
        goto L_0x0588;
    L_0x0609:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r17 = r2 - r21;
        goto L_0x05b0;
    L_0x0612:
        r2 = 0;
        r0 = r24;
        r0.mode = r2;
        goto L_0x003f;
    L_0x0619:
        if (r17 != 0) goto L_0x06fd;
    L_0x061b:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r0 = r21;
        if (r0 != r2) goto L_0x0643;
    L_0x0625:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        if (r2 == 0) goto L_0x0643;
    L_0x062d:
        r21 = 0;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r0 = r21;
        if (r0 >= r2) goto L_0x06e1;
    L_0x0639:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r2 = r2 - r21;
        r17 = r2 + -1;
    L_0x0643:
        if (r17 != 0) goto L_0x06fd;
    L_0x0645:
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r25 = r2.inflate_flush(r0);
        r0 = r24;
        r2 = r0.f3s;
        r0 = r2.write;
        r21 = r0;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r0 = r21;
        if (r0 >= r2) goto L_0x06eb;
    L_0x0669:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r2 = r2 - r21;
        r17 = r2 + -1;
    L_0x0673:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r0 = r21;
        if (r0 != r2) goto L_0x069b;
    L_0x067d:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        if (r2 == 0) goto L_0x069b;
    L_0x0685:
        r21 = 0;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r0 = r21;
        if (r0 >= r2) goto L_0x06f4;
    L_0x0691:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r2 = r2 - r21;
        r17 = r2 + -1;
    L_0x069b:
        if (r17 != 0) goto L_0x06fd;
    L_0x069d:
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r19 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r19;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        goto L_0x008a;
    L_0x06e1:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r17 = r2 - r21;
        goto L_0x0643;
    L_0x06eb:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r17 = r2 - r21;
        goto L_0x0673;
    L_0x06f4:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r17 = r2 - r21;
        goto L_0x069b;
    L_0x06fd:
        r25 = 0;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.window;
        r22 = r21 + 1;
        r0 = r24;
        r3 = r0.lit;
        r3 = (byte) r3;
        r2[r21] = r3;
        r17 = r17 + -1;
        r2 = 0;
        r0 = r24;
        r0.mode = r2;
        r21 = r22;
        goto L_0x003f;
    L_0x0719:
        r2 = 7;
        r0 = r16;
        if (r0 <= r2) goto L_0x0724;
    L_0x071e:
        r16 = r16 + -8;
        r18 = r18 + 1;
        r19 = r19 + -1;
    L_0x0724:
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r25 = r2.inflate_flush(r0);
        r0 = r24;
        r2 = r0.f3s;
        r0 = r2.write;
        r21 = r0;
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r0 = r21;
        if (r0 >= r2) goto L_0x07a4;
    L_0x0748:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r2 = r2 - r21;
        r17 = r2 + -1;
    L_0x0752:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.read;
        r0 = r24;
        r3 = r0.f3s;
        r3 = r3.write;
        if (r2 == r3) goto L_0x07ad;
    L_0x0760:
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r19 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r19;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        goto L_0x008a;
    L_0x07a4:
        r0 = r24;
        r2 = r0.f3s;
        r2 = r2.end;
        r17 = r2 - r21;
        goto L_0x0752;
    L_0x07ad:
        r2 = 8;
        r0 = r24;
        r0.mode = r2;
    L_0x07b3:
        r25 = 1;
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r19 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r19;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        goto L_0x008a;
    L_0x07f9:
        r25 = -3;
        r0 = r24;
        r2 = r0.f3s;
        r2.bitb = r11;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r16;
        r2.bitk = r0;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r18;
        r2.avail_in = r0;
        r0 = r24;
        r2 = r0.f4z;
        r4 = r2.total_in;
        r0 = r24;
        r3 = r0.f4z;
        r3 = r3.next_in_index;
        r3 = r19 - r3;
        r6 = (long) r3;
        r4 = r4 + r6;
        r2.total_in = r4;
        r0 = r24;
        r2 = r0.f4z;
        r0 = r19;
        r2.next_in_index = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r21;
        r2.write = r0;
        r0 = r24;
        r2 = r0.f3s;
        r0 = r25;
        r2 = r2.inflate_flush(r0);
        goto L_0x008a;
    L_0x083f:
        r13 = r14;
        goto L_0x051c;
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jcraft.jzlib.InfCodes.proc(int):int");
    }

    void free(ZStream z) {
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    int inflate_fast(int r31, int r32, int[] r33, int r34, int[] r35, int r36, com.jcraft.jzlib.InfBlocks r37, com.jcraft.jzlib.ZStream r38) {
        /*
        r30 = this;
        r0 = r38;
        r15 = r0.next_in_index;
        r0 = r38;
        r14 = r0.avail_in;
        r0 = r37;
        r6 = r0.bitb;
        r0 = r37;
        r10 = r0.bitk;
        r0 = r37;
        r0 = r0.write;
        r17 = r0;
        r0 = r37;
        r0 = r0.read;
        r25 = r0;
        r0 = r17;
        r1 = r25;
        if (r0 >= r1) goto L_0x0059;
    L_0x0022:
        r0 = r37;
        r0 = r0.read;
        r25 = r0;
        r25 = r25 - r17;
        r11 = r25 + -1;
    L_0x002c:
        r25 = inflate_mask;
        r13 = r25[r31];
        r25 = inflate_mask;
        r12 = r25[r32];
        r18 = r17;
        r16 = r15;
    L_0x0038:
        r25 = 20;
        r0 = r25;
        if (r10 >= r0) goto L_0x0062;
    L_0x003e:
        r14 = r14 + -1;
        r0 = r38;
        r0 = r0.next_in;
        r25 = r0;
        r15 = r16 + 1;
        r25 = r25[r16];
        r0 = r25;
        r0 = r0 & 255;
        r25 = r0;
        r25 = r25 << r10;
        r6 = r6 | r25;
        r10 = r10 + 8;
        r16 = r15;
        goto L_0x0038;
    L_0x0059:
        r0 = r37;
        r0 = r0.end;
        r25 = r0;
        r11 = r25 - r17;
        goto L_0x002c;
    L_0x0062:
        r21 = r6 & r13;
        r22 = r33;
        r23 = r34;
        r25 = r23 + r21;
        r24 = r25 * 3;
        r9 = r22[r24];
        if (r9 != 0) goto L_0x00e9;
    L_0x0070:
        r25 = r24 + 1;
        r25 = r22[r25];
        r6 = r6 >> r25;
        r25 = r24 + 1;
        r25 = r22[r25];
        r10 = r10 - r25;
        r0 = r37;
        r0 = r0.window;
        r25 = r0;
        r17 = r18 + 1;
        r26 = r24 + 2;
        r26 = r22[r26];
        r0 = r26;
        r0 = (byte) r0;
        r26 = r0;
        r25[r18] = r26;
        r11 = r11 + -1;
        r15 = r16;
    L_0x0093:
        r25 = 258; // 0x102 float:3.62E-43 double:1.275E-321;
        r0 = r25;
        if (r11 < r0) goto L_0x009f;
    L_0x0099:
        r25 = 10;
        r0 = r25;
        if (r14 >= r0) goto L_0x03d5;
    L_0x009f:
        r0 = r38;
        r0 = r0.avail_in;
        r25 = r0;
        r7 = r25 - r14;
        r25 = r10 >> 3;
        r0 = r25;
        if (r0 >= r7) goto L_0x00af;
    L_0x00ad:
        r7 = r10 >> 3;
    L_0x00af:
        r14 = r14 + r7;
        r15 = r15 - r7;
        r25 = r7 << 3;
        r10 = r10 - r25;
        r0 = r37;
        r0.bitb = r6;
        r0 = r37;
        r0.bitk = r10;
        r0 = r38;
        r0.avail_in = r14;
        r0 = r38;
        r0 = r0.total_in;
        r26 = r0;
        r0 = r38;
        r0 = r0.next_in_index;
        r25 = r0;
        r25 = r15 - r25;
        r0 = r25;
        r0 = (long) r0;
        r28 = r0;
        r26 = r26 + r28;
        r0 = r26;
        r2 = r38;
        r2.total_in = r0;
        r0 = r38;
        r0.next_in_index = r15;
        r0 = r17;
        r1 = r37;
        r1.write = r0;
        r25 = 0;
    L_0x00e8:
        return r25;
    L_0x00e9:
        r25 = r24 + 1;
        r25 = r22[r25];
        r6 = r6 >> r25;
        r25 = r24 + 1;
        r25 = r22[r25];
        r10 = r10 - r25;
        r25 = r9 & 16;
        if (r25 == 0) goto L_0x02ee;
    L_0x00f9:
        r9 = r9 & 15;
        r25 = r24 + 2;
        r25 = r22[r25];
        r26 = inflate_mask;
        r26 = r26[r9];
        r26 = r26 & r6;
        r7 = r25 + r26;
        r6 = r6 >> r9;
        r10 = r10 - r9;
    L_0x0109:
        r25 = 15;
        r0 = r25;
        if (r10 >= r0) goto L_0x012a;
    L_0x010f:
        r14 = r14 + -1;
        r0 = r38;
        r0 = r0.next_in;
        r25 = r0;
        r15 = r16 + 1;
        r25 = r25[r16];
        r0 = r25;
        r0 = r0 & 255;
        r25 = r0;
        r25 = r25 << r10;
        r6 = r6 | r25;
        r10 = r10 + 8;
        r16 = r15;
        goto L_0x0109;
    L_0x012a:
        r21 = r6 & r12;
        r22 = r35;
        r23 = r36;
        r25 = r23 + r21;
        r24 = r25 * 3;
        r9 = r22[r24];
    L_0x0136:
        r25 = r24 + 1;
        r25 = r22[r25];
        r6 = r6 >> r25;
        r25 = r24 + 1;
        r25 = r22[r25];
        r10 = r10 - r25;
        r25 = r9 & 16;
        if (r25 == 0) goto L_0x027e;
    L_0x0146:
        r9 = r9 & 15;
    L_0x0148:
        if (r10 >= r9) goto L_0x0165;
    L_0x014a:
        r14 = r14 + -1;
        r0 = r38;
        r0 = r0.next_in;
        r25 = r0;
        r15 = r16 + 1;
        r25 = r25[r16];
        r0 = r25;
        r0 = r0 & 255;
        r25 = r0;
        r25 = r25 << r10;
        r6 = r6 | r25;
        r10 = r10 + 8;
        r16 = r15;
        goto L_0x0148;
    L_0x0165:
        r25 = r24 + 2;
        r25 = r22[r25];
        r26 = inflate_mask;
        r26 = r26[r9];
        r26 = r26 & r6;
        r8 = r25 + r26;
        r6 = r6 >> r9;
        r10 = r10 - r9;
        r11 = r11 - r7;
        r0 = r18;
        if (r0 < r8) goto L_0x01fe;
    L_0x0178:
        r19 = r18 - r8;
        r25 = r18 - r19;
        if (r25 <= 0) goto L_0x01dc;
    L_0x017e:
        r25 = 2;
        r26 = r18 - r19;
        r0 = r25;
        r1 = r26;
        if (r0 <= r1) goto L_0x01dc;
    L_0x0188:
        r0 = r37;
        r0 = r0.window;
        r25 = r0;
        r17 = r18 + 1;
        r0 = r37;
        r0 = r0.window;
        r26 = r0;
        r20 = r19 + 1;
        r26 = r26[r19];
        r25[r18] = r26;
        r0 = r37;
        r0 = r0.window;
        r25 = r0;
        r18 = r17 + 1;
        r0 = r37;
        r0 = r0.window;
        r26 = r0;
        r19 = r20 + 1;
        r26 = r26[r20];
        r25[r17] = r26;
        r7 = r7 + -2;
        r17 = r18;
    L_0x01b4:
        r25 = r17 - r19;
        if (r25 <= 0) goto L_0x025e;
    L_0x01b8:
        r25 = r17 - r19;
        r0 = r25;
        if (r7 <= r0) goto L_0x025e;
    L_0x01be:
        r0 = r37;
        r0 = r0.window;
        r25 = r0;
        r18 = r17 + 1;
        r0 = r37;
        r0 = r0.window;
        r26 = r0;
        r20 = r19 + 1;
        r26 = r26[r19];
        r25[r17] = r26;
        r7 = r7 + -1;
        if (r7 != 0) goto L_0x03db;
    L_0x01d6:
        r17 = r18;
        r15 = r16;
        goto L_0x0093;
    L_0x01dc:
        r0 = r37;
        r0 = r0.window;
        r25 = r0;
        r0 = r37;
        r0 = r0.window;
        r26 = r0;
        r27 = 2;
        r0 = r25;
        r1 = r19;
        r2 = r26;
        r3 = r18;
        r4 = r27;
        java.lang.System.arraycopy(r0, r1, r2, r3, r4);
        r17 = r18 + 2;
        r19 = r19 + 2;
        r7 = r7 + -2;
        goto L_0x01b4;
    L_0x01fe:
        r19 = r18 - r8;
    L_0x0200:
        r0 = r37;
        r0 = r0.end;
        r25 = r0;
        r19 = r19 + r25;
        if (r19 < 0) goto L_0x0200;
    L_0x020a:
        r0 = r37;
        r0 = r0.end;
        r25 = r0;
        r9 = r25 - r19;
        if (r7 <= r9) goto L_0x03e7;
    L_0x0214:
        r7 = r7 - r9;
        r25 = r18 - r19;
        if (r25 <= 0) goto L_0x0241;
    L_0x0219:
        r25 = r18 - r19;
        r0 = r25;
        if (r9 <= r0) goto L_0x0241;
    L_0x021f:
        r17 = r18;
    L_0x0221:
        r0 = r37;
        r0 = r0.window;
        r25 = r0;
        r18 = r17 + 1;
        r0 = r37;
        r0 = r0.window;
        r26 = r0;
        r20 = r19 + 1;
        r26 = r26[r19];
        r25[r17] = r26;
        r9 = r9 + -1;
        if (r9 != 0) goto L_0x03e1;
    L_0x0239:
        r19 = r20;
        r17 = r18;
    L_0x023d:
        r19 = 0;
        goto L_0x01b4;
    L_0x0241:
        r0 = r37;
        r0 = r0.window;
        r25 = r0;
        r0 = r37;
        r0 = r0.window;
        r26 = r0;
        r0 = r25;
        r1 = r19;
        r2 = r26;
        r3 = r18;
        java.lang.System.arraycopy(r0, r1, r2, r3, r9);
        r17 = r18 + r9;
        r19 = r19 + r9;
        r9 = 0;
        goto L_0x023d;
    L_0x025e:
        r0 = r37;
        r0 = r0.window;
        r25 = r0;
        r0 = r37;
        r0 = r0.window;
        r26 = r0;
        r0 = r25;
        r1 = r19;
        r2 = r26;
        r3 = r17;
        java.lang.System.arraycopy(r0, r1, r2, r3, r7);
        r17 = r17 + r7;
        r19 = r19 + r7;
        r7 = 0;
        r15 = r16;
        goto L_0x0093;
    L_0x027e:
        r25 = r9 & 64;
        if (r25 != 0) goto L_0x0298;
    L_0x0282:
        r25 = r24 + 2;
        r25 = r22[r25];
        r21 = r21 + r25;
        r25 = inflate_mask;
        r25 = r25[r9];
        r25 = r25 & r6;
        r21 = r21 + r25;
        r25 = r23 + r21;
        r24 = r25 * 3;
        r9 = r22[r24];
        goto L_0x0136;
    L_0x0298:
        r25 = "invalid distance code";
        r0 = r25;
        r1 = r38;
        r1.msg = r0;
        r0 = r38;
        r0 = r0.avail_in;
        r25 = r0;
        r7 = r25 - r14;
        r25 = r10 >> 3;
        r0 = r25;
        if (r0 >= r7) goto L_0x02b0;
    L_0x02ae:
        r7 = r10 >> 3;
    L_0x02b0:
        r14 = r14 + r7;
        r15 = r16 - r7;
        r25 = r7 << 3;
        r10 = r10 - r25;
        r0 = r37;
        r0.bitb = r6;
        r0 = r37;
        r0.bitk = r10;
        r0 = r38;
        r0.avail_in = r14;
        r0 = r38;
        r0 = r0.total_in;
        r26 = r0;
        r0 = r38;
        r0 = r0.next_in_index;
        r25 = r0;
        r25 = r15 - r25;
        r0 = r25;
        r0 = (long) r0;
        r28 = r0;
        r26 = r26 + r28;
        r0 = r26;
        r2 = r38;
        r2.total_in = r0;
        r0 = r38;
        r0.next_in_index = r15;
        r0 = r18;
        r1 = r37;
        r1.write = r0;
        r25 = -3;
        r17 = r18;
        goto L_0x00e8;
    L_0x02ee:
        r25 = r9 & 64;
        if (r25 != 0) goto L_0x032d;
    L_0x02f2:
        r25 = r24 + 2;
        r25 = r22[r25];
        r21 = r21 + r25;
        r25 = inflate_mask;
        r25 = r25[r9];
        r25 = r25 & r6;
        r21 = r21 + r25;
        r25 = r23 + r21;
        r24 = r25 * 3;
        r9 = r22[r24];
        if (r9 != 0) goto L_0x00e9;
    L_0x0308:
        r25 = r24 + 1;
        r25 = r22[r25];
        r6 = r6 >> r25;
        r25 = r24 + 1;
        r25 = r22[r25];
        r10 = r10 - r25;
        r0 = r37;
        r0 = r0.window;
        r25 = r0;
        r17 = r18 + 1;
        r26 = r24 + 2;
        r26 = r22[r26];
        r0 = r26;
        r0 = (byte) r0;
        r26 = r0;
        r25[r18] = r26;
        r11 = r11 + -1;
        r15 = r16;
        goto L_0x0093;
    L_0x032d:
        r25 = r9 & 32;
        if (r25 == 0) goto L_0x037f;
    L_0x0331:
        r0 = r38;
        r0 = r0.avail_in;
        r25 = r0;
        r7 = r25 - r14;
        r25 = r10 >> 3;
        r0 = r25;
        if (r0 >= r7) goto L_0x0341;
    L_0x033f:
        r7 = r10 >> 3;
    L_0x0341:
        r14 = r14 + r7;
        r15 = r16 - r7;
        r25 = r7 << 3;
        r10 = r10 - r25;
        r0 = r37;
        r0.bitb = r6;
        r0 = r37;
        r0.bitk = r10;
        r0 = r38;
        r0.avail_in = r14;
        r0 = r38;
        r0 = r0.total_in;
        r26 = r0;
        r0 = r38;
        r0 = r0.next_in_index;
        r25 = r0;
        r25 = r15 - r25;
        r0 = r25;
        r0 = (long) r0;
        r28 = r0;
        r26 = r26 + r28;
        r0 = r26;
        r2 = r38;
        r2.total_in = r0;
        r0 = r38;
        r0.next_in_index = r15;
        r0 = r18;
        r1 = r37;
        r1.write = r0;
        r25 = 1;
        r17 = r18;
        goto L_0x00e8;
    L_0x037f:
        r25 = "invalid literal/length code";
        r0 = r25;
        r1 = r38;
        r1.msg = r0;
        r0 = r38;
        r0 = r0.avail_in;
        r25 = r0;
        r7 = r25 - r14;
        r25 = r10 >> 3;
        r0 = r25;
        if (r0 >= r7) goto L_0x0397;
    L_0x0395:
        r7 = r10 >> 3;
    L_0x0397:
        r14 = r14 + r7;
        r15 = r16 - r7;
        r25 = r7 << 3;
        r10 = r10 - r25;
        r0 = r37;
        r0.bitb = r6;
        r0 = r37;
        r0.bitk = r10;
        r0 = r38;
        r0.avail_in = r14;
        r0 = r38;
        r0 = r0.total_in;
        r26 = r0;
        r0 = r38;
        r0 = r0.next_in_index;
        r25 = r0;
        r25 = r15 - r25;
        r0 = r25;
        r0 = (long) r0;
        r28 = r0;
        r26 = r26 + r28;
        r0 = r26;
        r2 = r38;
        r2.total_in = r0;
        r0 = r38;
        r0.next_in_index = r15;
        r0 = r18;
        r1 = r37;
        r1.write = r0;
        r25 = -3;
        r17 = r18;
        goto L_0x00e8;
    L_0x03d5:
        r18 = r17;
        r16 = r15;
        goto L_0x0038;
    L_0x03db:
        r19 = r20;
        r17 = r18;
        goto L_0x01be;
    L_0x03e1:
        r19 = r20;
        r17 = r18;
        goto L_0x0221;
    L_0x03e7:
        r17 = r18;
        goto L_0x01b4;
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jcraft.jzlib.InfCodes.inflate_fast(int, int, int[], int, int[], int, com.jcraft.jzlib.InfBlocks, com.jcraft.jzlib.ZStream):int");
    }
}
