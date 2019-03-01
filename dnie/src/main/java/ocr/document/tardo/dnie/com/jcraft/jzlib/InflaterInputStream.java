package com.jcraft.jzlib;

import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class InflaterInputStream extends FilterInputStream {
    protected static final int DEFAULT_BUFSIZE = 512;
    /* renamed from: b */
    private byte[] f12b;
    protected byte[] buf;
    private byte[] byte1;
    private boolean close_in;
    private boolean closed;
    private boolean eof;
    protected final Inflater inflater;
    protected boolean myinflater;

    public InflaterInputStream(InputStream in) throws IOException {
        this(in, new Inflater());
        this.myinflater = true;
    }

    public InflaterInputStream(InputStream in, Inflater inflater) throws IOException {
        this(in, inflater, 512);
    }

    public InflaterInputStream(InputStream in, Inflater inflater, int size) throws IOException {
        this(in, inflater, size, true);
    }

    public InflaterInputStream(InputStream in, Inflater inflater, int size, boolean close_in) throws IOException {
        super(in);
        this.closed = false;
        this.eof = false;
        this.close_in = true;
        this.myinflater = false;
        this.byte1 = new byte[1];
        this.f12b = new byte[512];
        if (in == null || inflater == null) {
            throw new NullPointerException();
        } else if (size <= 0) {
            throw new IllegalArgumentException("buffer size must be greater than 0");
        } else {
            this.inflater = inflater;
            this.buf = new byte[size];
            this.close_in = close_in;
        }
    }

    public int read() throws IOException {
        if (this.closed) {
            throw new IOException("Stream closed");
        } else if (read(this.byte1, 0, 1) == -1) {
            return -1;
        } else {
            return this.byte1[0] & 255;
        }
    }

    public int read(byte[] b, int off, int len) throws IOException {
        if (this.closed) {
            throw new IOException("Stream closed");
        } else if (b == null) {
            throw new NullPointerException();
        } else if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return 0;
        } else {
            if (this.eof) {
                return -1;
            }
            int n = 0;
            this.inflater.setOutput(b, off, len);
            while (!this.eof) {
                if (this.inflater.avail_in == 0) {
                    fill();
                }
                int err = this.inflater.inflate(0);
                n += this.inflater.next_out_index - off;
                off = this.inflater.next_out_index;
                switch (err) {
                    case JZlib.Z_DATA_ERROR /*-3*/:
                        throw new IOException(this.inflater.msg);
                    case 1:
                    case 2:
                        this.eof = true;
                        if (err == 2) {
                            return -1;
                        }
                        break;
                }
                if (this.inflater.avail_out == 0) {
                    return n;
                }
            }
            return n;
        }
    }

    public int available() throws IOException {
        if (this.closed) {
            throw new IOException("Stream closed");
        } else if (this.eof) {
            return 0;
        } else {
            return 1;
        }
    }

    public long skip(long n) throws IOException {
        if (n < 0) {
            throw new IllegalArgumentException("negative skip length");
        } else if (this.closed) {
            throw new IOException("Stream closed");
        } else {
            int max = (int) Math.min(n, 2147483647L);
            int total = 0;
            while (total < max) {
                int len = max - total;
                if (len > this.f12b.length) {
                    len = this.f12b.length;
                }
                len = read(this.f12b, 0, len);
                if (len == -1) {
                    this.eof = true;
                    break;
                }
                total += len;
            }
            return (long) total;
        }
    }

    public void close() throws IOException {
        if (!this.closed) {
            if (this.myinflater) {
                this.inflater.end();
            }
            if (this.close_in) {
                this.in.close();
            }
            this.closed = true;
        }
    }

    protected void fill() throws IOException {
        if (this.closed) {
            throw new IOException("Stream closed");
        }
        int len = this.in.read(this.buf, 0, this.buf.length);
        if (len == -1) {
            if (this.inflater.istate.wrap == 0 && !this.inflater.finished()) {
                this.buf[0] = (byte) 0;
                len = 1;
            } else if (this.inflater.istate.was != -1) {
                throw new IOException("footer is not found");
            } else {
                throw new EOFException("Unexpected end of ZLIB input stream");
            }
        }
        this.inflater.setInput(this.buf, 0, len, true);
    }

    public boolean markSupported() {
        return false;
    }

    public synchronized void mark(int readlimit) {
    }

    public synchronized void reset() throws IOException {
        throw new IOException("mark/reset not supported");
    }

    public long getTotalIn() {
        return this.inflater.getTotalIn();
    }

    public long getTotalOut() {
        return this.inflater.getTotalOut();
    }

    public byte[] getAvailIn() {
        if (this.inflater.avail_in <= 0) {
            return null;
        }
        byte[] tmp = new byte[this.inflater.avail_in];
        System.arraycopy(this.inflater.next_in, this.inflater.next_in_index, tmp, 0, this.inflater.avail_in);
        return tmp;
    }

    public void readHeader() throws IOException {
        byte[] empty = "".getBytes();
        this.inflater.setInput(empty, 0, 0, false);
        this.inflater.setOutput(empty, 0, 0);
        int err = this.inflater.inflate(0);
        if (this.inflater.istate.inParsingHeader()) {
            byte[] b1 = new byte[1];
            while (this.in.read(b1) > 0) {
                this.inflater.setInput(b1);
                if (this.inflater.inflate(0) != 0) {
                    throw new IOException(this.inflater.msg);
                } else if (!this.inflater.istate.inParsingHeader()) {
                    return;
                }
            }
            throw new IOException("no input");
        }
    }

    public Inflater getInflater() {
        return this.inflater;
    }
}
