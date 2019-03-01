package jj2000.j2k.io;

import java.io.EOFException;
import java.io.IOException;

public interface RandomAccessIO extends BinaryDataInput, BinaryDataOutput {
    void close() throws IOException;

    int getPos() throws IOException;

    int length() throws IOException;

    int read() throws EOFException, IOException;

    void readFully(byte[] bArr, int i, int i2) throws IOException;

    void seek(int i) throws IOException;

    void write(int i) throws IOException;
}
