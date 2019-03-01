package com.jcraft.jzlib;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class DeflaterOutputStream extends FilterOutputStream {
    protected static final int DEFAULT_BUFSIZE = 512;
    private final byte[] buf1;
    protected byte[] buffer;
    private boolean close_out;
    private boolean closed;
    protected final Deflater deflater;
    protected boolean mydeflater;
    private boolean syncFlush;

    public DeflaterOutputStream(OutputStream out) throws IOException {
        this(out, new Deflater(-1), 512, true);
        this.mydeflater = true;
    }

    public DeflaterOutputStream(OutputStream out, Deflater def) throws IOException {
        this(out, def, 512, true);
    }

    public DeflaterOutputStream(OutputStream out, Deflater deflater, int size) throws IOException {
        this(out, deflater, size, true);
    }

    public DeflaterOutputStream(OutputStream out, Deflater deflater, int size, boolean close_out) throws IOException {
        super(out);
        this.closed = false;
        this.syncFlush = false;
        this.buf1 = new byte[1];
        this.mydeflater = false;
        this.close_out = true;
        if (out == null || deflater == null) {
            throw new NullPointerException();
        } else if (size <= 0) {
            throw new IllegalArgumentException("buffer size must be greater than 0");
        } else {
            this.deflater = deflater;
            this.buffer = new byte[size];
            this.close_out = close_out;
        }
    }

    public void write(int b) throws IOException {
        this.buf1[0] = (byte) (b & 255);
        write(this.buf1, 0, 1);
    }

    public void write(byte[] b, int off, int len) throws IOException {
        if (this.deflater.finished()) {
            throw new IOException("finished");
        }
        int i;
        if (off < 0) {
            i = 1;
        } else {
            i = 0;
        }
        if (((off + len > b.length ? 1 : 0) | (i | (len < 0 ? 1 : 0))) != 0) {
            throw new IndexOutOfBoundsException();
        } else if (len != 0) {
            int flush;
            if (this.syncFlush) {
                flush = 2;
            } else {
                flush = 0;
            }
            this.deflater.setInput(b, off, len, true);
            while (this.deflater.avail_in > 0) {
                if (deflate(flush) == 1) {
                    return;
                }
            }
        }
    }

    public void finish() throws IOException {
        while (!this.deflater.finished()) {
            deflate(4);
        }
    }

    public void close() throws IOException {
        if (!this.closed) {
            finish();
            if (this.mydeflater) {
                this.deflater.end();
            }
            if (this.close_out) {
                this.out.close();
            }
            this.closed = true;
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    protected int deflate(int r7) throws java.io.IOException {
        /*
        r6 = this;
        r5 = 0;
        r2 = r6.deflater;
        r3 = r6.buffer;
        r4 = r6.buffer;
        r4 = r4.length;
        r2.setOutput(r3, r5, r4);
        r2 = r6.deflater;
        r0 = r2.deflate(r7);
        switch(r0) {
            case -5: goto L_0x001c;
            case 0: goto L_0x0025;
            case 1: goto L_0x0025;
            default: goto L_0x0014;
        };
    L_0x0014:
        r2 = new java.io.IOException;
        r3 = "failed to deflate";
        r2.<init>(r3);
        throw r2;
    L_0x001c:
        r2 = r6.deflater;
        r2 = r2.avail_in;
        if (r2 > 0) goto L_0x0014;
    L_0x0022:
        r2 = 4;
        if (r7 == r2) goto L_0x0014;
    L_0x0025:
        r2 = r6.deflater;
        r1 = r2.next_out_index;
        if (r1 <= 0) goto L_0x0032;
    L_0x002b:
        r2 = r6.out;
        r3 = r6.buffer;
        r2.write(r3, r5, r1);
    L_0x0032:
        return r0;
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jcraft.jzlib.DeflaterOutputStream.deflate(int):int");
    }

    public void flush() throws IOException {
        if (this.syncFlush && !this.deflater.finished()) {
            int err;
            do {
                err = deflate(2);
                if (this.deflater.next_out_index < this.buffer.length) {
                    break;
                }
            } while (err != 1);
        }
        this.out.flush();
    }

    public long getTotalIn() {
        return this.deflater.getTotalIn();
    }

    public long getTotalOut() {
        return this.deflater.getTotalOut();
    }

    public void setSyncFlush(boolean syncFlush) {
        this.syncFlush = syncFlush;
    }

    public boolean getSyncFlush() {
        return this.syncFlush;
    }

    public Deflater getDeflater() {
        return this.deflater;
    }
}
