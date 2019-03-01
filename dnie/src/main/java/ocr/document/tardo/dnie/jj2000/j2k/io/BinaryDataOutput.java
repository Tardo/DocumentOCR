package jj2000.j2k.io;

import java.io.IOException;

public interface BinaryDataOutput {
    void flush() throws IOException;

    int getByteOrdering();

    void writeByte(int i) throws IOException;

    void writeDouble(double d) throws IOException;

    void writeFloat(float f) throws IOException;

    void writeInt(int i) throws IOException;

    void writeLong(long j) throws IOException;

    void writeShort(int i) throws IOException;
}
