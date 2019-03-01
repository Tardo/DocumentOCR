package com.jcraft.jzlib;

import custom.org.apache.harmony.xnet.provider.jsse.Handshake;
import org.bouncycastle.crypto.tls.CipherSuite;

final class Tree {
    private static final int BL_CODES = 19;
    static final int Buf_size = 16;
    static final int DIST_CODE_LEN = 512;
    private static final int D_CODES = 30;
    static final int END_BLOCK = 256;
    private static final int HEAP_SIZE = 573;
    private static final int LENGTH_CODES = 29;
    private static final int LITERALS = 256;
    private static final int L_CODES = 286;
    private static final int MAX_BITS = 15;
    static final int MAX_BL_BITS = 7;
    static final int REPZ_11_138 = 18;
    static final int REPZ_3_10 = 17;
    static final int REP_3_6 = 16;
    static final byte[] _dist_code = new byte[]{(byte) 0, (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 4, (byte) 5, (byte) 5, (byte) 6, (byte) 6, (byte) 6, (byte) 6, (byte) 7, (byte) 7, (byte) 7, (byte) 7, (byte) 8, (byte) 8, (byte) 8, (byte) 8, (byte) 8, (byte) 8, (byte) 8, (byte) 8, (byte) 9, (byte) 9, (byte) 9, (byte) 9, (byte) 9, (byte) 9, (byte) 9, (byte) 9, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 10, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 11, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, (byte) 13, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, (byte) 0, (byte) 0, (byte) 16, (byte) 17, (byte) 18, (byte) 18, (byte) 19, (byte) 19, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 28, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29, (byte) 29};
    static final byte[] _length_code = new byte[]{(byte) 0, (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6, (byte) 7, (byte) 8, (byte) 8, (byte) 9, (byte) 9, (byte) 10, (byte) 10, (byte) 11, (byte) 11, (byte) 12, (byte) 12, (byte) 12, (byte) 12, (byte) 13, (byte) 13, (byte) 13, (byte) 13, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.SERVER_HELLO_DONE, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, Handshake.CERTIFICATE_VERIFY, (byte) 16, (byte) 16, (byte) 16, (byte) 16, (byte) 16, (byte) 16, (byte) 16, (byte) 16, (byte) 17, (byte) 17, (byte) 17, (byte) 17, (byte) 17, (byte) 17, (byte) 17, (byte) 17, (byte) 18, (byte) 18, (byte) 18, (byte) 18, (byte) 18, (byte) 18, (byte) 18, (byte) 18, (byte) 19, (byte) 19, (byte) 19, (byte) 19, (byte) 19, (byte) 19, (byte) 19, (byte) 19, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, Handshake.FINISHED, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 21, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 22, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 23, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 24, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 25, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 26, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 27, (byte) 28};
    static final int[] base_dist = new int[]{0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576};
    static final int[] base_length = new int[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, 192, 224, 0};
    static final byte[] bl_order = new byte[]{(byte) 16, (byte) 17, (byte) 18, (byte) 0, (byte) 8, (byte) 7, (byte) 9, (byte) 6, (byte) 10, (byte) 5, (byte) 11, (byte) 4, (byte) 12, (byte) 3, (byte) 13, (byte) 2, Handshake.SERVER_HELLO_DONE, (byte) 1, Handshake.CERTIFICATE_VERIFY};
    static final int[] extra_blbits = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7};
    static final int[] extra_dbits = new int[]{0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
    static final int[] extra_lbits = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    static short[] next_code = new short[16];
    short[] dyn_tree;
    int max_code;
    StaticTree stat_desc;

    Tree() {
    }

    static int d_code(int dist) {
        return dist < 256 ? _dist_code[dist] : _dist_code[(dist >>> 7) + 256];
    }

    void gen_bitlen(Deflate s) {
        int bits;
        short[] tree = this.dyn_tree;
        short[] stree = this.stat_desc.static_tree;
        int[] extra = this.stat_desc.extra_bits;
        int base = this.stat_desc.extra_base;
        short max_length = this.stat_desc.max_length;
        int overflow = 0;
        for (bits = 0; bits <= 15; bits++) {
            s.bl_count[bits] = (short) 0;
        }
        tree[(s.heap[s.heap_max] * 2) + 1] = (short) 0;
        int h = s.heap_max + 1;
        while (h < HEAP_SIZE) {
            int n = s.heap[h];
            bits = tree[(tree[(n * 2) + 1] * 2) + 1] + 1;
            if (bits > max_length) {
                bits = max_length;
                overflow++;
            }
            tree[(n * 2) + 1] = (short) bits;
            if (n <= this.max_code) {
                short[] sArr = s.bl_count;
                sArr[bits] = (short) (sArr[bits] + 1);
                int xbits = 0;
                if (n >= base) {
                    xbits = extra[n - base];
                }
                short f = tree[n * 2];
                s.opt_len += (bits + xbits) * f;
                if (stree != null) {
                    s.static_len += (stree[(n * 2) + 1] + xbits) * f;
                }
            }
            h++;
        }
        if (overflow != 0) {
            do {
                bits = max_length - 1;
                while (s.bl_count[bits] == (short) 0) {
                    bits--;
                }
                sArr = s.bl_count;
                sArr[bits] = (short) (sArr[bits] - 1);
                sArr = s.bl_count;
                int i = bits + 1;
                sArr[i] = (short) (sArr[i] + 2);
                sArr = s.bl_count;
                sArr[max_length] = (short) (sArr[max_length] - 1);
                overflow -= 2;
            } while (overflow > 0);
            for (short bits2 = max_length; bits2 != (short) 0; bits2--) {
                n = s.bl_count[bits2];
                while (n != 0) {
                    h--;
                    int m = s.heap[h];
                    if (m <= this.max_code) {
                        if (tree[(m * 2) + 1] != bits2) {
                            s.opt_len = (int) (((long) s.opt_len) + ((((long) bits2) - ((long) tree[(m * 2) + 1])) * ((long) tree[m * 2])));
                            tree[(m * 2) + 1] = (short) bits2;
                        }
                        n--;
                    }
                }
            }
        }
    }

    void build_tree(Deflate s) {
        int n;
        int node;
        short[] tree = this.dyn_tree;
        short[] stree = this.stat_desc.static_tree;
        int elems = this.stat_desc.elems;
        int max_code = -1;
        s.heap_len = 0;
        s.heap_max = HEAP_SIZE;
        for (n = 0; n < elems; n++) {
            if (tree[n * 2] != (short) 0) {
                int[] iArr = s.heap;
                int i = s.heap_len + 1;
                s.heap_len = i;
                max_code = n;
                iArr[i] = n;
                s.depth[n] = (byte) 0;
            } else {
                tree[(n * 2) + 1] = (short) 0;
            }
        }
        while (s.heap_len < 2) {
            iArr = s.heap;
            i = s.heap_len + 1;
            s.heap_len = i;
            if (max_code < 2) {
                max_code++;
                node = max_code;
            } else {
                node = 0;
            }
            iArr[i] = node;
            tree[node * 2] = (short) 1;
            s.depth[node] = (byte) 0;
            s.opt_len--;
            if (stree != null) {
                s.static_len -= stree[(node * 2) + 1];
            }
        }
        this.max_code = max_code;
        for (n = s.heap_len / 2; n >= 1; n--) {
            s.pqdownheap(tree, n);
        }
        node = elems;
        while (true) {
            n = s.heap[1];
            int[] iArr2 = s.heap;
            iArr = s.heap;
            i = s.heap_len;
            s.heap_len = i - 1;
            iArr2[1] = iArr[i];
            s.pqdownheap(tree, 1);
            int m = s.heap[1];
            iArr2 = s.heap;
            int i2 = s.heap_max - 1;
            s.heap_max = i2;
            iArr2[i2] = n;
            iArr2 = s.heap;
            i2 = s.heap_max - 1;
            s.heap_max = i2;
            iArr2[i2] = m;
            tree[node * 2] = (short) (tree[n * 2] + tree[m * 2]);
            s.depth[node] = (byte) (Math.max(s.depth[n], s.depth[m]) + 1);
            int i3 = (n * 2) + 1;
            short s2 = (short) node;
            tree[(m * 2) + 1] = s2;
            tree[i3] = s2;
            int node2 = node + 1;
            s.heap[1] = node;
            s.pqdownheap(tree, 1);
            if (s.heap_len < 2) {
                iArr2 = s.heap;
                i2 = s.heap_max - 1;
                s.heap_max = i2;
                iArr2[i2] = s.heap[1];
                gen_bitlen(s);
                gen_codes(tree, max_code, s.bl_count);
                return;
            }
            node = node2;
        }
    }

    static synchronized void gen_codes(short[] tree, int max_code, short[] bl_count) {
        synchronized (Tree.class) {
            short code = (short) 0;
            next_code[0] = (short) 0;
            for (int bits = 1; bits <= 15; bits++) {
                code = (short) ((bl_count[bits - 1] + code) << 1);
                next_code[bits] = code;
            }
            for (int n = 0; n <= max_code; n++) {
                int len = tree[(n * 2) + 1];
                if (len != 0) {
                    int i = n * 2;
                    short[] sArr = next_code;
                    short s = sArr[len];
                    sArr[len] = (short) (s + 1);
                    tree[i] = (short) bi_reverse(s, len);
                }
            }
        }
    }

    static int bi_reverse(int code, int len) {
        int res = 0;
        do {
            code >>>= 1;
            res = (res | (code & 1)) << 1;
            len--;
        } while (len > 0);
        return res >>> 1;
    }
}
