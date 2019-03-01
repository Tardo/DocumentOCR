package com.jcraft.jzlib;

public final class Deflater extends ZStream {
    private static final int DEF_WBITS = 15;
    private static final int MAX_MEM_LEVEL = 9;
    private static final int MAX_WBITS = 15;
    private static final int Z_BUF_ERROR = -5;
    private static final int Z_DATA_ERROR = -3;
    private static final int Z_ERRNO = -1;
    private static final int Z_FINISH = 4;
    private static final int Z_FULL_FLUSH = 3;
    private static final int Z_MEM_ERROR = -4;
    private static final int Z_NEED_DICT = 2;
    private static final int Z_NO_FLUSH = 0;
    private static final int Z_OK = 0;
    private static final int Z_PARTIAL_FLUSH = 1;
    private static final int Z_STREAM_END = 1;
    private static final int Z_STREAM_ERROR = -2;
    private static final int Z_SYNC_FLUSH = 2;
    private static final int Z_VERSION_ERROR = -6;
    private boolean finished;

    public Deflater() {
        this.finished = false;
    }

    public Deflater(int level) throws GZIPException {
        this(level, 15);
    }

    public Deflater(int level, boolean nowrap) throws GZIPException {
        this(level, 15, nowrap);
    }

    public Deflater(int level, int bits) throws GZIPException {
        this(level, bits, false);
    }

    public Deflater(int level, int bits, boolean nowrap) throws GZIPException {
        this.finished = false;
        int ret = init(level, bits, nowrap);
        if (ret != 0) {
            throw new GZIPException(ret + ": " + this.msg);
        }
    }

    public Deflater(int level, int bits, int memlevel) throws GZIPException {
        this.finished = false;
        int ret = init(level, bits, memlevel);
        if (ret != 0) {
            throw new GZIPException(ret + ": " + this.msg);
        }
    }

    public int init(int level) {
        return init(level, 15);
    }

    public int init(int level, boolean nowrap) {
        return init(level, 15, nowrap);
    }

    public int init(int level, int bits) {
        return init(level, bits, false);
    }

    public int init(int level, int bits, int memlevel) {
        this.finished = false;
        this.dstate = new Deflate(this);
        return this.dstate.deflateInit(level, bits, memlevel);
    }

    public int init(int level, int bits, boolean nowrap) {
        this.finished = false;
        this.dstate = new Deflate(this);
        Deflate deflate = this.dstate;
        if (nowrap) {
            bits = -bits;
        }
        return deflate.deflateInit(level, bits);
    }

    public int deflate(int flush) {
        if (this.dstate == null) {
            return -2;
        }
        int ret = this.dstate.deflate(flush);
        if (ret != 1) {
            return ret;
        }
        this.finished = true;
        return ret;
    }

    public int end() {
        this.finished = true;
        if (this.dstate == null) {
            return -2;
        }
        int ret = this.dstate.deflateEnd();
        this.dstate = null;
        free();
        return ret;
    }

    public int params(int level, int strategy) {
        if (this.dstate == null) {
            return -2;
        }
        return this.dstate.deflateParams(level, strategy);
    }

    public int setDictionary(byte[] dictionary, int dictLength) {
        if (this.dstate == null) {
            return -2;
        }
        return this.dstate.deflateSetDictionary(dictionary, dictLength);
    }

    public boolean finished() {
        return this.finished;
    }

    public int copy(Deflater src) {
        this.finished = src.finished;
        return Deflate.deflateCopy(this, src);
    }
}
