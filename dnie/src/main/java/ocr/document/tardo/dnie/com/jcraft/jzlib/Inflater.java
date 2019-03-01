package com.jcraft.jzlib;

public final class Inflater extends ZStream {
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

    public Inflater() {
        this.finished = false;
        init();
    }

    public Inflater(int w) throws GZIPException {
        this(w, false);
    }

    public Inflater(int w, boolean nowrap) throws GZIPException {
        this.finished = false;
        int ret = init(w, nowrap);
        if (ret != 0) {
            throw new GZIPException(ret + ": " + this.msg);
        }
    }

    public int init() {
        return init(15);
    }

    public int init(boolean nowrap) {
        return init(15, nowrap);
    }

    public int init(int w) {
        return init(w, false);
    }

    public int init(int w, boolean nowrap) {
        this.finished = false;
        this.istate = new Inflate(this);
        Inflate inflate = this.istate;
        if (nowrap) {
            w = -w;
        }
        return inflate.inflateInit(w);
    }

    public int inflate(int f) {
        if (this.istate == null) {
            return -2;
        }
        int ret = this.istate.inflate(f);
        if (ret != 1) {
            return ret;
        }
        this.finished = true;
        return ret;
    }

    public int end() {
        this.finished = true;
        if (this.istate == null) {
            return -2;
        }
        return this.istate.inflateEnd();
    }

    public int sync() {
        if (this.istate == null) {
            return -2;
        }
        return this.istate.inflateSync();
    }

    public int syncPoint() {
        if (this.istate == null) {
            return -2;
        }
        return this.istate.inflateSyncPoint();
    }

    public int setDictionary(byte[] dictionary, int dictLength) {
        if (this.istate == null) {
            return -2;
        }
        return this.istate.inflateSetDictionary(dictionary, dictLength);
    }

    public boolean finished() {
        return this.istate.mode == 12;
    }
}
