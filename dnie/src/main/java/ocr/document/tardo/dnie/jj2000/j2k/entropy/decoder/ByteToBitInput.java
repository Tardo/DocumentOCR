package jj2000.j2k.entropy.decoder;

public class ByteToBitInput {
    int bbuf;
    int bpos = -1;
    ByteInputBuffer in;

    public ByteToBitInput(ByteInputBuffer in) {
        this.in = in;
    }

    public final int readBit() {
        if (this.bpos < 0) {
            if ((this.bbuf & 255) != 255) {
                this.bbuf = this.in.read();
                this.bpos = 7;
            } else {
                this.bbuf = this.in.read();
                this.bpos = 6;
            }
        }
        int i = this.bbuf;
        int i2 = this.bpos;
        this.bpos = i2 - 1;
        return (i >> i2) & 1;
    }

    public boolean checkBytePadding() {
        if (this.bpos < 0 && (this.bbuf & 255) == 255) {
            this.bbuf = this.in.read();
            this.bpos = 6;
        }
        if (this.bpos >= 0 && (this.bbuf & ((1 << (this.bpos + 1)) - 1)) != (85 >> (7 - this.bpos))) {
            return true;
        }
        if (this.bbuf != -1) {
            if (this.bbuf == 255 && this.bpos == 0) {
                if ((this.in.read() & 255) >= 128) {
                    return true;
                }
            } else if (this.in.read() != -1) {
                return true;
            }
        }
        return false;
    }

    final void flush() {
        this.bbuf = 0;
        this.bpos = -1;
    }

    final void setByteArray(byte[] buf, int off, int len) {
        this.in.setByteArray(buf, off, len);
        this.bbuf = 0;
        this.bpos = -1;
    }
}
