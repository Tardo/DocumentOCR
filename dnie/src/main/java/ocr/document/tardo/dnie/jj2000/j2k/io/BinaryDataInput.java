package jj2000.j2k.io;

import java.io.EOFException;
import java.io.IOException;

public interface BinaryDataInput {
    int getByteOrdering();

    byte readByte() throws EOFException, IOException;

    double readDouble() throws EOFException, IOException;

    float readFloat() throws EOFException, IOException;

    int readInt() throws EOFException, IOException;

    long readLong() throws EOFException, IOException;

    short readShort() throws EOFException, IOException;

    int readUnsignedByte() throws EOFException, IOException;

    long readUnsignedInt() throws EOFException, IOException;

    int readUnsignedShort() throws EOFException, IOException;

    int skipBytes(int i) throws EOFException, IOException;
}
