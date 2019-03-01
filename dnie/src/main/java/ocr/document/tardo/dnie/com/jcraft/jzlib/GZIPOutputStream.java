package com.jcraft.jzlib;

import java.io.IOException;
import java.io.OutputStream;

public class GZIPOutputStream extends DeflaterOutputStream {
    public GZIPOutputStream(OutputStream out) throws IOException {
        this(out, 512);
    }

    public GZIPOutputStream(OutputStream out, int size) throws IOException {
        this(out, size, true);
    }

    public GZIPOutputStream(OutputStream out, int size, boolean close_out) throws IOException {
        this(out, new Deflater(-1, 31), size, close_out);
        this.mydeflater = true;
    }

    public GZIPOutputStream(OutputStream out, Deflater deflater, int size, boolean close_out) throws IOException {
        super(out, deflater, size, close_out);
    }

    private void check() throws GZIPException {
        if (this.deflater.dstate.status != 42) {
            throw new GZIPException("header is already written.");
        }
    }

    public void setModifiedTime(long mtime) throws GZIPException {
        check();
        this.deflater.dstate.getGZIPHeader().setModifiedTime(mtime);
    }

    public void setOS(int os) throws GZIPException {
        check();
        this.deflater.dstate.getGZIPHeader().setOS(os);
    }

    public void setName(String name) throws GZIPException {
        check();
        this.deflater.dstate.getGZIPHeader().setName(name);
    }

    public void setComment(String comment) throws GZIPException {
        check();
        this.deflater.dstate.getGZIPHeader().setComment(comment);
    }

    public long getCRC() throws GZIPException {
        if (this.deflater.dstate.status == 666) {
            return this.deflater.dstate.getGZIPHeader().getCRC();
        }
        throw new GZIPException("checksum is not calculated yet.");
    }
}
