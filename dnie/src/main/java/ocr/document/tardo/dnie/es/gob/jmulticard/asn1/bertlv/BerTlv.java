package es.gob.jmulticard.asn1.bertlv;

import java.io.ByteArrayInputStream;
import org.bouncycastle.asn1.eac.CertificateBody;

public final class BerTlv {
    private int length;
    private BerTlvIdentifier tag;
    private byte[] value;

    public BerTlvIdentifier getTag() {
        return this.tag;
    }

    public byte[] getValue() {
        if (this.value == null) {
            return null;
        }
        byte[] out = new byte[this.value.length];
        System.arraycopy(this.value, 0, out, 0, this.value.length);
        return out;
    }

    public static BerTlv getInstance(ByteArrayInputStream stream) {
        BerTlv tlv = new BerTlv();
        tlv.decode(stream);
        return tlv;
    }

    private void decode(ByteArrayInputStream stream) throws IndexOutOfBoundsException {
        this.tag = new BerTlvIdentifier();
        this.tag.decode(stream);
        int tmpLength = stream.read();
        if (tmpLength <= CertificateBody.profileType) {
            this.length = tmpLength;
        } else if (tmpLength == 128) {
            this.length = tmpLength;
        } else {
            int numberOfLengthOctets = tmpLength & CertificateBody.profileType;
            tmpLength = 0;
            for (int i = 0; i < numberOfLengthOctets; i++) {
                tmpLength = (tmpLength << 8) | stream.read();
            }
            this.length = tmpLength;
        }
        if (this.length == 128) {
            stream.mark(0);
            int prevOctet = 1;
            int len = 0;
            while (true) {
                len++;
                int curOctet = stream.read();
                if (prevOctet == 0 && curOctet == 0) {
                    break;
                }
                prevOctet = curOctet;
            }
            len -= 2;
            this.value = new byte[len];
            stream.reset();
            if (len != stream.read(this.value, 0, len)) {
                throw new IndexOutOfBoundsException("La longitud de los datos leidos no coincide con el parametro indicado");
            }
            this.length = len;
            return;
        }
        this.value = new byte[this.length];
        if (this.length != stream.read(this.value, 0, this.length)) {
            throw new IndexOutOfBoundsException("La longitud de los datos leidos no coincide con el parametro indicado");
        }
    }

    public String toString() {
        return "[TLV: T=" + this.tag + ";L=" + this.length + ";V=" + (this.value == null ? "null" : this.value.length + " bytes") + "]";
    }
}
