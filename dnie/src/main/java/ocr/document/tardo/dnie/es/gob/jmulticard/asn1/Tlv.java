package es.gob.jmulticard.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public final class Tlv {
    private final byte[] bytes;
    private final int length;
    private final byte tag;
    private final int valueOffset;

    public Tlv(byte t, byte[] value) {
        if (value == null) {
            throw new IllegalArgumentException("El valor del TLV no puede ser nulo");
        }
        int iExtLen;
        this.valueOffset = 2;
        this.tag = t;
        this.length = value.length;
        if (value.length >= 128) {
            iExtLen = 3;
        } else {
            iExtLen = 2;
        }
        this.bytes = new byte[(value.length + iExtLen)];
        this.bytes[0] = t;
        if (value.length >= 128) {
            this.bytes[1] = (byte) -127;
            this.bytes[2] = (byte) value.length;
        } else {
            this.bytes[1] = (byte) value.length;
        }
        System.arraycopy(value, 0, this.bytes, iExtLen, value.length);
    }

    public Tlv(byte[] buffer) throws TlvException {
        if (buffer == null || buffer.length < 3) {
            throw new IllegalArgumentException("El TLV no puede ser nulo ni medir menos de tres octetos");
        }
        byte[] tempBytes = new byte[buffer.length];
        System.arraycopy(buffer, 0, tempBytes, 0, buffer.length);
        int offset = 0 + 1;
        this.tag = tempBytes[0];
        if ((this.tag & 31) == 31) {
            throw new TlvException("El tipo del TLV es invalido");
        }
        boolean indefinite;
        int offset2 = offset + 1;
        int size = tempBytes[offset] & 255;
        if (size == 128) {
            indefinite = true;
        } else {
            indefinite = false;
        }
        if (indefinite) {
            if ((this.tag & 32) == 0) {
                throw new TlvException("Longitud del TLV invalida");
            }
        } else if (size >= 128) {
            int sizeLen = size - 128;
            if (sizeLen > 3) {
                throw new TlvException("TLV demasiado largo");
            }
            size = 0;
            offset = offset2;
            while (sizeLen > 0) {
                size = (size << 8) + (tempBytes[offset] & 255);
                sizeLen--;
                offset++;
            }
            offset2 = offset;
        }
        this.length = size;
        this.valueOffset = offset2;
        this.bytes = new byte[(this.valueOffset + this.length)];
        System.arraycopy(tempBytes, 0, this.bytes, 0, this.valueOffset + this.length);
    }

    public byte[] getBytes() {
        byte[] out = new byte[this.bytes.length];
        System.arraycopy(this.bytes, 0, out, 0, this.bytes.length);
        return out;
    }

    public int getLength() {
        return this.length;
    }

    public byte getTag() {
        return this.tag;
    }

    public byte[] getValue() {
        byte[] out = new byte[this.length];
        System.arraycopy(this.bytes, this.valueOffset, out, 0, this.length);
        return out;
    }

    public static Tlv decode(ByteArrayInputStream recordOfTlv) throws IOException {
        byte tag = (byte) recordOfTlv.read();
        if ((tag & 31) == 31) {
            throw new IOException("El tipo del TLV es invalido");
        }
        int size = recordOfTlv.read() & 255;
        if (size == 128) {
            if ((tag & 32) == 0) {
                throw new IOException("Longitud del TLV invalida");
            }
        } else if (size >= 128) {
            int sizeLen = size - 128;
            if (sizeLen > 3) {
                throw new IOException("TLV demasiado largo");
            }
            size = 0;
            while (sizeLen > 0) {
                size = (size << 8) + (recordOfTlv.read() & 255);
                sizeLen--;
            }
        }
        byte[] value = new byte[size];
        if (value.length == recordOfTlv.read(value)) {
            return new Tlv(tag, value);
        }
        throw new IndexOutOfBoundsException("La longitud de los datos leidos no coincide con el parametro indicado");
    }
}
