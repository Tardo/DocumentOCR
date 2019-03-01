package com.jcraft.jzlib;

import java.io.IOException;
import java.io.InputStream;

public class GZIPInputStream extends InflaterInputStream {
    public GZIPInputStream(InputStream in) throws IOException {
        this(in, 512, true);
    }

    public GZIPInputStream(InputStream in, int size, boolean close_in) throws IOException {
        this(in, new Inflater(31), size, close_in);
        this.myinflater = true;
    }

    public GZIPInputStream(InputStream in, Inflater inflater, int size, boolean close_in) throws IOException {
        super(in, inflater, size, close_in);
    }

    public long getModifiedtime() {
        return this.inflater.istate.getGZIPHeader().getModifiedTime();
    }

    public int getOS() {
        return this.inflater.istate.getGZIPHeader().getOS();
    }

    public String getName() {
        return this.inflater.istate.getGZIPHeader().getName();
    }

    public String getComment() {
        return this.inflater.istate.getGZIPHeader().getComment();
    }

    public long getCRC() throws GZIPException {
        if (this.inflater.istate.mode == 12) {
            return this.inflater.istate.getGZIPHeader().getCRC();
        }
        throw new GZIPException("checksum is not calculated yet.");
    }

    public void readHeader() throws IOException {
        byte[] empty = "".getBytes();
        this.inflater.setOutput(empty, 0, 0);
        this.inflater.setInput(empty, 0, 0, false);
        byte[] b = new byte[10];
        int n = fill(b);
        if (n != 10) {
            if (n > 0) {
                this.inflater.setInput(b, 0, n, false);
                this.inflater.next_in_index = 0;
                this.inflater.avail_in = n;
            }
            throw new IOException("no input");
        }
        this.inflater.setInput(b, 0, n, false);
        byte[] b1 = new byte[1];
        do {
            if (this.inflater.avail_in <= 0) {
                if (this.in.read(b1) <= 0) {
                    throw new IOException("no input");
                }
                this.inflater.setInput(b1, 0, 1, true);
            }
            if (this.inflater.inflate(0) != 0) {
                Inflater inflater;
                int len = 2048 - this.inflater.next_in.length;
                if (len > 0) {
                    byte[] tmp = new byte[len];
                    n = fill(tmp);
                    if (n > 0) {
                        inflater = this.inflater;
                        inflater.avail_in += this.inflater.next_in_index;
                        this.inflater.next_in_index = 0;
                        this.inflater.setInput(tmp, 0, n, true);
                    }
                }
                inflater = this.inflater;
                inflater.avail_in += this.inflater.next_in_index;
                this.inflater.next_in_index = 0;
                throw new IOException(this.inflater.msg);
            }
        } while (this.inflater.istate.inParsingHeader());
    }

    private int fill(byte[] buf) {
        int len = buf.length;
        int n = 0;
        do {
            int i = -1;
            try {
                i = this.in.read(buf, n, buf.length - n);
            } catch (IOException e) {
            }
            if (i == -1) {
                break;
            }
            n += i;
        } while (n < len);
        return n;
    }
}
