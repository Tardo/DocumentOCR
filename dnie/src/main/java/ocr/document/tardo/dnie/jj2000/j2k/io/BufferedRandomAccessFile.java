package jj2000.j2k.io;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

public abstract class BufferedRandomAccessFile implements RandomAccessIO, EndianType {
    protected byte[] byteBuffer;
    protected boolean byteBufferChanged;
    protected int byteOrdering;
    private String fileName;
    protected boolean isEOFInBuffer;
    private boolean isReadOnly;
    protected int maxByte;
    protected int offset;
    protected int pos;
    private RandomAccessFile theFile;

    protected BufferedRandomAccessFile(File file, String mode, int bufferSize) throws IOException {
        this.isReadOnly = true;
        this.fileName = file.getName();
        if (mode.equals("rw") || mode.equals("rw+")) {
            this.isReadOnly = false;
            if (mode.equals("rw") && file.exists()) {
                file.delete();
            }
            mode = "rw";
        }
        this.theFile = new RandomAccessFile(file, mode);
        this.byteBuffer = new byte[bufferSize];
        readNewBuffer(0);
    }

    protected BufferedRandomAccessFile(File file, String mode) throws IOException {
        this(file, mode, 512);
    }

    protected BufferedRandomAccessFile(String name, String mode, int bufferSize) throws IOException {
        this(new File(name), mode, bufferSize);
    }

    protected BufferedRandomAccessFile(String name, String mode) throws IOException {
        this(name, mode, 512);
    }

    protected final void readNewBuffer(int off) throws IOException {
        if (this.byteBufferChanged) {
            flush();
        }
        if (!this.isReadOnly || ((long) off) < this.theFile.length()) {
            this.offset = off;
            this.theFile.seek((long) this.offset);
            this.maxByte = this.theFile.read(this.byteBuffer, 0, this.byteBuffer.length);
            this.pos = 0;
            if (this.maxByte < this.byteBuffer.length) {
                this.isEOFInBuffer = true;
                if (this.maxByte == -1) {
                    this.maxByte++;
                    return;
                }
                return;
            }
            this.isEOFInBuffer = false;
            return;
        }
        throw new EOFException();
    }

    public void close() throws IOException {
        flush();
        this.byteBuffer = null;
        this.theFile.close();
    }

    public int getPos() {
        return this.offset + this.pos;
    }

    public int length() throws IOException {
        int len = (int) this.theFile.length();
        return this.offset + this.maxByte <= len ? len : this.offset + this.maxByte;
    }

    public void seek(int off) throws IOException {
        if (off < this.offset || off >= this.offset + this.byteBuffer.length) {
            readNewBuffer(off);
        } else if (this.isReadOnly && this.isEOFInBuffer && off > this.offset + this.maxByte) {
            throw new EOFException();
        } else {
            this.pos = off - this.offset;
        }
    }

    public final int read() throws IOException, EOFException {
        if (this.pos < this.maxByte) {
            byte[] bArr = this.byteBuffer;
            int i = this.pos;
            this.pos = i + 1;
            return bArr[i] & 255;
        } else if (this.isEOFInBuffer) {
            this.pos = this.maxByte + 1;
            throw new EOFException();
        } else {
            readNewBuffer(this.offset + this.pos);
            return read();
        }
    }

    public final void readFully(byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            if (this.pos < this.maxByte) {
                int clen = this.maxByte - this.pos;
                if (clen > len) {
                    clen = len;
                }
                System.arraycopy(this.byteBuffer, this.pos, b, off, clen);
                this.pos += clen;
                off += clen;
                len -= clen;
            } else if (this.isEOFInBuffer) {
                this.pos = this.maxByte + 1;
                throw new EOFException();
            } else {
                readNewBuffer(this.offset + this.pos);
            }
        }
    }

    public final void write(int b) throws IOException {
        if (this.pos >= this.byteBuffer.length) {
            readNewBuffer(this.offset + this.pos);
            write(b);
        } else if (this.isReadOnly) {
            throw new IOException("File is read only");
        } else {
            this.byteBuffer[this.pos] = (byte) b;
            if (this.pos >= this.maxByte) {
                this.maxByte = this.pos + 1;
            }
            this.pos++;
            this.byteBufferChanged = true;
        }
    }

    public final void write(byte b) throws IOException {
        if (this.pos >= this.byteBuffer.length) {
            readNewBuffer(this.offset + this.pos);
            write(b);
        } else if (this.isReadOnly) {
            throw new IOException("File is read only");
        } else {
            this.byteBuffer[this.pos] = b;
            if (this.pos >= this.maxByte) {
                this.maxByte = this.pos + 1;
            }
            this.pos++;
            this.byteBufferChanged = true;
        }
    }

    public final void write(byte[] b, int offset, int length) throws IOException {
        int stop = offset + length;
        if (stop > b.length) {
            throw new ArrayIndexOutOfBoundsException(b.length);
        }
        for (int i = offset; i < stop; i++) {
            write(b[i]);
        }
    }

    public final void writeByte(int v) throws IOException {
        write(v);
    }

    public final void flush() throws IOException {
        if (this.byteBufferChanged) {
            this.theFile.seek((long) this.offset);
            this.theFile.write(this.byteBuffer, 0, this.maxByte);
            this.byteBufferChanged = false;
        }
    }

    public final byte readByte() throws EOFException, IOException {
        if (this.pos < this.maxByte) {
            byte[] bArr = this.byteBuffer;
            int i = this.pos;
            this.pos = i + 1;
            return bArr[i];
        } else if (this.isEOFInBuffer) {
            this.pos = this.maxByte + 1;
            throw new EOFException();
        } else {
            readNewBuffer(this.offset + this.pos);
            return readByte();
        }
    }

    public final int readUnsignedByte() throws EOFException, IOException {
        return read();
    }

    public int getByteOrdering() {
        return this.byteOrdering;
    }

    public int skipBytes(int n) throws EOFException, IOException {
        if (n < 0) {
            throw new IllegalArgumentException("Can not skip negative number of bytes");
        }
        if (n <= this.maxByte - this.pos) {
            this.pos += n;
        } else {
            seek((this.offset + this.pos) + n);
        }
        return n;
    }

    public String toString() {
        return "BufferedRandomAccessFile: " + this.fileName + " (" + (this.isReadOnly ? "read only" : "read/write") + ")";
    }
}
