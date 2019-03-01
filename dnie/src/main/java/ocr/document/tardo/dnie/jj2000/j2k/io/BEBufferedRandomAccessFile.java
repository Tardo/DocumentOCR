package jj2000.j2k.io;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;

public class BEBufferedRandomAccessFile extends BufferedRandomAccessFile implements RandomAccessIO, EndianType {
    public BEBufferedRandomAccessFile(File file, String mode, int bufferSize) throws IOException {
        super(file, mode, bufferSize);
        this.byteOrdering = 0;
    }

    public BEBufferedRandomAccessFile(File file, String mode) throws IOException {
        super(file, mode);
        this.byteOrdering = 0;
    }

    public BEBufferedRandomAccessFile(String name, String mode, int bufferSize) throws IOException {
        super(name, mode, bufferSize);
        this.byteOrdering = 0;
    }

    public BEBufferedRandomAccessFile(String name, String mode) throws IOException {
        super(name, mode);
        this.byteOrdering = 0;
    }

    public final void writeShort(int v) throws IOException {
        write(v >>> 8);
        write(v);
    }

    public final void writeInt(int v) throws IOException {
        write(v >>> 24);
        write(v >>> 16);
        write(v >>> 8);
        write(v);
    }

    public final void writeLong(long v) throws IOException {
        write((int) (v >>> 56));
        write((int) (v >>> 48));
        write((int) (v >>> 40));
        write((int) (v >>> 32));
        write((int) (v >>> 24));
        write((int) (v >>> 16));
        write((int) (v >>> 8));
        write((int) v);
    }

    public final void writeFloat(float v) throws IOException {
        int intV = Float.floatToIntBits(v);
        write(intV >>> 24);
        write(intV >>> 16);
        write(intV >>> 8);
        write(intV);
    }

    public final void writeDouble(double v) throws IOException {
        long longV = Double.doubleToLongBits(v);
        write((int) (longV >>> 56));
        write((int) (longV >>> 48));
        write((int) (longV >>> 40));
        write((int) (longV >>> 32));
        write((int) (longV >>> 24));
        write((int) (longV >>> 16));
        write((int) (longV >>> 8));
        write((int) longV);
    }

    public final short readShort() throws IOException, EOFException {
        return (short) ((read() << 8) | read());
    }

    public final int readUnsignedShort() throws IOException, EOFException {
        return (read() << 8) | read();
    }

    public final int readInt() throws IOException, EOFException {
        return (((read() << 24) | (read() << 16)) | (read() << 8)) | read();
    }

    public final long readUnsignedInt() throws IOException, EOFException {
        return (long) ((((read() << 24) | (read() << 16)) | (read() << 8)) | read());
    }

    public final long readLong() throws IOException, EOFException {
        return (((((((((long) read()) << 56) | (((long) read()) << 48)) | (((long) read()) << 40)) | (((long) read()) << 32)) | (((long) read()) << 24)) | (((long) read()) << 16)) | (((long) read()) << 8)) | ((long) read());
    }

    public final float readFloat() throws EOFException, IOException {
        return Float.intBitsToFloat((((read() << 24) | (read() << 16)) | (read() << 8)) | read());
    }

    public final double readDouble() throws IOException, EOFException {
        return Double.longBitsToDouble((((((((((long) read()) << 56) | (((long) read()) << 48)) | (((long) read()) << 40)) | (((long) read()) << 32)) | (((long) read()) << 24)) | (((long) read()) << 16)) | (((long) read()) << 8)) | ((long) read()));
    }

    public String toString() {
        return super.toString() + "\nBig-Endian ordering";
    }
}
