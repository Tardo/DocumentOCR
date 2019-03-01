package com.jcraft.jzlib;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

@Deprecated
public class ZOutputStream extends FilterOutputStream {
    protected byte[] buf;
    private byte[] buf1;
    protected int bufsize;
    protected boolean compress;
    private DeflaterOutputStream dos;
    private boolean end;
    protected int flush;
    private Inflater inflater;
    protected OutputStream out;

    public ZOutputStream(OutputStream out) throws IOException {
        super(out);
        this.bufsize = 512;
        this.flush = 0;
        this.buf = new byte[this.bufsize];
        this.end = false;
        this.buf1 = new byte[1];
        this.out = out;
        this.inflater = new Inflater();
        this.inflater.init();
        this.compress = false;
    }

    public ZOutputStream(OutputStream out, int level) throws IOException {
        this(out, level, false);
    }

    public ZOutputStream(OutputStream out, int level, boolean nowrap) throws IOException {
        super(out);
        this.bufsize = 512;
        this.flush = 0;
        this.buf = new byte[this.bufsize];
        this.end = false;
        this.buf1 = new byte[1];
        this.out = out;
        this.dos = new DeflaterOutputStream(out, new Deflater(level, nowrap));
        this.compress = true;
    }

    public void write(int b) throws IOException {
        this.buf1[0] = (byte) b;
        write(this.buf1, 0, 1);
    }

    public void write(byte[] b, int off, int len) throws IOException {
        if (len != 0) {
            if (this.compress) {
                this.dos.write(b, off, len);
                return;
            }
            this.inflater.setInput(b, off, len, true);
            int err = 0;
            while (this.inflater.avail_in > 0) {
                this.inflater.setOutput(this.buf, 0, this.buf.length);
                err = this.inflater.inflate(this.flush);
                if (this.inflater.next_out_index > 0) {
                    this.out.write(this.buf, 0, this.inflater.next_out_index);
                    continue;
                }
                if (err != 0) {
                    break;
                }
            }
            if (err != 0) {
                throw new ZStreamException("inflating: " + this.inflater.msg);
            }
        }
    }

    public int getFlushMode() {
        return this.flush;
    }

    public void setFlushMode(int flush) {
        this.flush = flush;
    }

    public void finish() throws IOException {
        if (this.compress) {
            int tmp = this.flush;
            try {
                write("".getBytes(), 0, 0);
            } finally {
                int flush = tmp;
            }
        } else {
            this.dos.finish();
        }
        flush();
    }

    public synchronized void end() {
        if (!this.end) {
            if (this.compress) {
                try {
                    this.dos.finish();
                } catch (Exception e) {
                }
            } else {
                this.inflater.end();
            }
            this.end = true;
        }
    }

    public void close() throws IOException {
        try {
            finish();
        } catch (IOException e) {
        } catch (Throwable th) {
            end();
            this.out.close();
            this.out = null;
        }
        end();
        this.out.close();
        this.out = null;
    }

    public long getTotalIn() {
        if (this.compress) {
            return this.dos.getTotalIn();
        }
        return this.inflater.total_in;
    }

    public long getTotalOut() {
        if (this.compress) {
            return this.dos.getTotalOut();
        }
        return this.inflater.total_out;
    }

    public void flush() throws IOException {
        this.out.flush();
    }
}
