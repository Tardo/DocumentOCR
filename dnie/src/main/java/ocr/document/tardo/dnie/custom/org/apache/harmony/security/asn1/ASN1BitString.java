package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;

public class ASN1BitString extends ASN1StringType {
    private static final ASN1BitString ASN1 = new ASN1BitString();

    public static class ASN1NamedBitList extends ASN1BitString {
        private static final int INDEFINITE_SIZE = -1;
        private static final byte[] SET_MASK = new byte[]{Byte.MIN_VALUE, (byte) 64, (byte) 32, (byte) 16, (byte) 8, (byte) 4, (byte) 2, (byte) 1};
        private static final BitString emptyString = new BitString(new byte[0], 0);
        private final int maxBits;
        private final int minBits;

        public ASN1NamedBitList() {
            this.minBits = -1;
            this.maxBits = -1;
        }

        public ASN1NamedBitList(int minBits) {
            this.minBits = minBits;
            this.maxBits = -1;
        }

        public ASN1NamedBitList(int minBits, int maxBits) {
            this.minBits = minBits;
            this.maxBits = maxBits;
        }

        public Object getDecodedObject(BerInputStream in) throws IOException {
            boolean[] value;
            int unusedBits = in.buffer[in.contentOffset];
            int bitsNumber = ((in.length - 1) * 8) - unusedBits;
            if (this.maxBits == -1) {
                if (this.minBits == -1) {
                    value = new boolean[bitsNumber];
                } else if (bitsNumber > this.minBits) {
                    value = new boolean[bitsNumber];
                } else {
                    value = new boolean[this.minBits];
                }
            } else if (bitsNumber > this.maxBits) {
                throw new ASN1Exception(Messages.getString("security.97"));
            } else {
                value = new boolean[this.maxBits];
            }
            if (bitsNumber != 0) {
                int k;
                boolean z;
                int i = 1;
                int j = 0;
                byte octet = in.buffer[in.contentOffset + 1];
                int size = in.length - 1;
                while (i < size) {
                    k = 0;
                    while (k < 8) {
                        if ((SET_MASK[k] & octet) != 0) {
                            z = true;
                        } else {
                            z = false;
                        }
                        value[j] = z;
                        k++;
                        j++;
                    }
                    i++;
                    octet = in.buffer[in.contentOffset + i];
                    i++;
                }
                k = 0;
                while (k < 8 - unusedBits) {
                    if ((SET_MASK[k] & octet) != 0) {
                        z = true;
                    } else {
                        z = false;
                    }
                    value[j] = z;
                    k++;
                    j++;
                }
            }
            return value;
        }

        public void setEncodingContent(BerOutputStream out) {
            boolean[] toEncode = (boolean[]) out.content;
            int index = toEncode.length - 1;
            while (index > -1 && !toEncode[index]) {
                index--;
            }
            if (index == -1) {
                out.content = emptyString;
                out.length = 1;
                return;
            }
            int k;
            int unusedBits = 7 - (index % 8);
            byte[] bytes = new byte[((index / 8) + 1)];
            int j = 0;
            index = bytes.length - 1;
            for (int i = 0; i < index; i++) {
                k = 0;
                while (k < 8) {
                    if (toEncode[j]) {
                        bytes[i] = (byte) (bytes[i] | SET_MASK[k]);
                    }
                    k++;
                    j++;
                }
            }
            k = 0;
            while (k < 8 - unusedBits) {
                if (toEncode[j]) {
                    bytes[index] = (byte) (bytes[index] | SET_MASK[k]);
                }
                k++;
                j++;
            }
            out.content = new BitString(bytes, unusedBits);
            out.length = bytes.length + 1;
        }
    }

    public ASN1BitString() {
        super(3);
    }

    public static ASN1BitString getInstance() {
        return ASN1;
    }

    public Object decode(BerInputStream in) throws IOException {
        in.readBitString();
        if (in.isVerify) {
            return null;
        }
        return getDecodedObject(in);
    }

    public Object getDecodedObject(BerInputStream in) throws IOException {
        byte[] bytes = new byte[(in.length - 1)];
        System.arraycopy(in.buffer, in.contentOffset + 1, bytes, 0, in.length - 1);
        return new BitString(bytes, in.buffer[in.contentOffset]);
    }

    public void encodeContent(BerOutputStream out) {
        out.encodeBitString();
    }

    public void setEncodingContent(BerOutputStream out) {
        out.length = ((BitString) out.content).bytes.length + 1;
    }
}
