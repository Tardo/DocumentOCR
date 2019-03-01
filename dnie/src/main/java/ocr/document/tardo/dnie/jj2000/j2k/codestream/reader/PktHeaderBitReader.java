package jj2000.j2k.codestream.reader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import jj2000.j2k.io.RandomAccessIO;

class PktHeaderBitReader {
    ByteArrayInputStream bais;
    int bbuf;
    int bpos;
    RandomAccessIO in;
    int nextbbuf;
    boolean usebais = true;

    PktHeaderBitReader(RandomAccessIO in) {
        this.in = in;
    }

    PktHeaderBitReader(ByteArrayInputStream bais) {
        this.bais = bais;
    }

    final int readBit() throws IOException {
        if (this.bpos == 0) {
            if (this.bbuf != 255) {
                if (this.usebais) {
                    this.bbuf = this.bais.read();
                } else {
                    this.bbuf = this.in.read();
                }
                this.bpos = 8;
                if (this.bbuf == 255) {
                    if (this.usebais) {
                        this.nextbbuf = this.bais.read();
                    } else {
                        this.nextbbuf = this.in.read();
                    }
                }
            } else {
                this.bbuf = this.nextbbuf;
                this.bpos = 7;
            }
        }
        int i = this.bbuf;
        int i2 = this.bpos - 1;
        this.bpos = i2;
        return (i >> i2) & 1;
    }

    final int readBits(int n) throws IOException {
        if (n <= this.bpos) {
            int i = this.bbuf;
            int i2 = this.bpos - n;
            this.bpos = i2;
            return (i >> i2) & ((1 << n) - 1);
        }
        int bits = 0;
        do {
            n -= this.bpos;
            bits = (bits << this.bpos) | readBits(this.bpos);
            if (this.bbuf != 255) {
                if (this.usebais) {
                    this.bbuf = this.bais.read();
                } else {
                    this.bbuf = this.in.read();
                }
                this.bpos = 8;
                if (this.bbuf == 255) {
                    if (this.usebais) {
                        this.nextbbuf = this.bais.read();
                    } else {
                        this.nextbbuf = this.in.read();
                    }
                }
            } else {
                this.bbuf = this.nextbbuf;
                this.bpos = 7;
            }
        } while (n > this.bpos);
        bits <<= n;
        i = this.bbuf;
        i2 = this.bpos - n;
        this.bpos = i2;
        return bits | ((i >> i2) & ((1 << n) - 1));
    }

    void sync() {
        this.bbuf = 0;
        this.bpos = 0;
    }

    void setInput(RandomAccessIO in) {
        this.in = in;
        this.bbuf = 0;
        this.bpos = 0;
    }

    void setInput(ByteArrayInputStream bais) {
        this.bais = bais;
        this.bbuf = 0;
        this.bpos = 0;
    }
}
