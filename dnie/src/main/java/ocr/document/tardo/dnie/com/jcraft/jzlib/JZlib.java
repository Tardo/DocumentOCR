package com.jcraft.jzlib;

public final class JZlib {
    public static final int DEF_WBITS = 15;
    public static final int MAX_WBITS = 15;
    public static final byte Z_ASCII = (byte) 1;
    public static final int Z_BEST_COMPRESSION = 9;
    public static final int Z_BEST_SPEED = 1;
    public static final byte Z_BINARY = (byte) 0;
    public static final int Z_BUF_ERROR = -5;
    public static final int Z_DATA_ERROR = -3;
    public static final int Z_DEFAULT_COMPRESSION = -1;
    public static final int Z_DEFAULT_STRATEGY = 0;
    public static final int Z_ERRNO = -1;
    public static final int Z_FILTERED = 1;
    public static final int Z_FINISH = 4;
    public static final int Z_FULL_FLUSH = 3;
    public static final int Z_HUFFMAN_ONLY = 2;
    public static final int Z_MEM_ERROR = -4;
    public static final int Z_NEED_DICT = 2;
    public static final int Z_NO_COMPRESSION = 0;
    public static final int Z_NO_FLUSH = 0;
    public static final int Z_OK = 0;
    public static final int Z_PARTIAL_FLUSH = 1;
    public static final int Z_STREAM_END = 1;
    public static final int Z_STREAM_ERROR = -2;
    public static final int Z_SYNC_FLUSH = 2;
    public static final byte Z_UNKNOWN = (byte) 2;
    public static final int Z_VERSION_ERROR = -6;
    private static final String version = "1.1.0";

    public static String version() {
        return version;
    }

    public static long adler32_combine(long adler1, long adler2, long len2) {
        return Adler32.combine(adler1, adler2, len2);
    }

    public static long crc32_combine(long crc1, long crc2, long len2) {
        return CRC32.combine(crc1, crc2, len2);
    }
}
