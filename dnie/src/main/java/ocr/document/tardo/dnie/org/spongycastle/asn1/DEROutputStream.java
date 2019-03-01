package org.spongycastle.asn1;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.asn1.eac.CertificateBody;

public class DEROutputStream extends FilterOutputStream implements DERTags {
    public DEROutputStream(OutputStream os) {
        super(os);
    }

    private void writeLength(int length) throws IOException {
        if (length > CertificateBody.profileType) {
            int size = 1;
            int val = length;
            while (true) {
                val >>>= 8;
                if (val == 0) {
                    break;
                }
                size++;
            }
            write((byte) (size | 128));
            for (int i = (size - 1) * 8; i >= 0; i -= 8) {
                write((byte) (length >> i));
            }
            return;
        }
        write((byte) length);
    }

    void writeEncoded(int tag, byte[] bytes) throws IOException {
        write(tag);
        writeLength(bytes.length);
        write(bytes);
    }

    void writeTag(int flags, int tagNo) throws IOException {
        if (tagNo < 31) {
            write(flags | tagNo);
            return;
        }
        write(flags | 31);
        if (tagNo < 128) {
            write(tagNo);
            return;
        }
        byte[] stack = new byte[5];
        int pos = stack.length - 1;
        stack[pos] = (byte) (tagNo & CertificateBody.profileType);
        do {
            tagNo >>= 7;
            pos--;
            stack[pos] = (byte) ((tagNo & CertificateBody.profileType) | 128);
        } while (tagNo > CertificateBody.profileType);
        write(stack, pos, stack.length - pos);
    }

    void writeEncoded(int flags, int tagNo, byte[] bytes) throws IOException {
        writeTag(flags, tagNo);
        writeLength(bytes.length);
        write(bytes);
    }

    protected void writeNull() throws IOException {
        write(5);
        write(0);
    }

    public void write(byte[] buf) throws IOException {
        this.out.write(buf, 0, buf.length);
    }

    public void write(byte[] buf, int offSet, int len) throws IOException {
        this.out.write(buf, offSet, len);
    }

    public void writeObject(Object obj) throws IOException {
        if (obj == null) {
            writeNull();
        } else if (obj instanceof DERObject) {
            ((DERObject) obj).encode(this);
        } else if (obj instanceof DEREncodable) {
            ((DEREncodable) obj).getDERObject().encode(this);
        } else {
            throw new IOException("object not DEREncodable");
        }
    }
}
