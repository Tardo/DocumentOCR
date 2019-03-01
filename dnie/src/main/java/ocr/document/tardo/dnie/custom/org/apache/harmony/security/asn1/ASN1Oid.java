package custom.org.apache.harmony.security.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.eac.CertificateBody;

public class ASN1Oid extends ASN1Primitive {
    private static final ASN1Oid ASN1 = new ASN1Oid();
    private static final ASN1Oid STRING_OID = new C02531();

    /* renamed from: custom.org.apache.harmony.security.asn1.ASN1Oid$1 */
    static class C02531 extends ASN1Oid {
        C02531() {
        }

        public Object getDecodedObject(BerInputStream in) throws IOException {
            StringBuilder buf = new StringBuilder();
            int octet = in.buffer[in.contentOffset];
            int element = octet & CertificateBody.profileType;
            int index = 0;
            while ((octet & 128) != 0) {
                index++;
                octet = in.buffer[in.contentOffset + index];
                element = (element << 7) | (octet & CertificateBody.profileType);
            }
            if (element > 79) {
                buf.append('2');
                buf.append('.');
                buf.append(element - 80);
            } else {
                buf.append(element / 40);
                buf.append('.');
                buf.append(element % 40);
            }
            for (int j = 2; j < in.oidElement; j++) {
                buf.append('.');
                index++;
                octet = in.buffer[in.contentOffset + index];
                element = octet & CertificateBody.profileType;
                while ((octet & 128) != 0) {
                    index++;
                    octet = in.buffer[in.contentOffset + index];
                    element = (element << 7) | (octet & CertificateBody.profileType);
                }
                buf.append(element);
            }
            return buf.toString();
        }

        public void setEncodingContent(BerOutputStream out) {
            out.content = ObjectIdentifier.toIntArray((String) out.content);
            super.setEncodingContent(out);
        }
    }

    public ASN1Oid() {
        super(6);
    }

    public static ASN1Oid getInstance() {
        return ASN1;
    }

    public Object decode(BerInputStream in) throws IOException {
        in.readOID();
        if (in.isVerify) {
            return null;
        }
        return getDecodedObject(in);
    }

    public Object getDecodedObject(BerInputStream in) throws IOException {
        int[] oid = new int[in.oidElement];
        int id = 1;
        int i = 0;
        while (id < oid.length) {
            int octet = in.buffer[in.contentOffset + i];
            int oidElement = octet & CertificateBody.profileType;
            while ((octet & 128) != 0) {
                i++;
                octet = in.buffer[in.contentOffset + i];
                oidElement = (oidElement << 7) | (octet & CertificateBody.profileType);
            }
            oid[id] = oidElement;
            id++;
            i++;
        }
        if (oid[1] > 79) {
            oid[0] = 2;
            oid[1] = oid[1] - 80;
        } else {
            oid[0] = oid[1] / 40;
            oid[1] = oid[1] % 40;
        }
        return oid;
    }

    public void encodeContent(BerOutputStream out) {
        out.encodeOID();
    }

    public void setEncodingContent(BerOutputStream out) {
        int[] oid = (int[]) out.content;
        int length = 0;
        int elem = (oid[0] * 40) + oid[1];
        if (elem == 0) {
            length = 1;
        } else {
            while (elem > 0) {
                length++;
                elem >>= 7;
            }
        }
        for (int i = 2; i < oid.length; i++) {
            if (oid[i] == 0) {
                length++;
            } else {
                for (elem = oid[i]; elem > 0; elem >>= 7) {
                    length++;
                }
            }
        }
        out.length = length;
    }

    public static ASN1Oid getInstanceForString() {
        return STRING_OID;
    }
}
