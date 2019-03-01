package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.bouncycastle.asn1.eac.CertificateBody;
import org.spongycastle.util.Arrays;

public class DERApplicationSpecific extends ASN1Object {
    private final boolean isConstructed;
    private final byte[] octets;
    private final int tag;

    DERApplicationSpecific(boolean isConstructed, int tag, byte[] octets) {
        this.isConstructed = isConstructed;
        this.tag = tag;
        this.octets = octets;
    }

    public DERApplicationSpecific(int tag, byte[] octets) {
        this(false, tag, octets);
    }

    public DERApplicationSpecific(int tag, DEREncodable object) throws IOException {
        this(true, tag, object);
    }

    public DERApplicationSpecific(boolean explicit, int tag, DEREncodable object) throws IOException {
        byte[] data = object.getDERObject().getDEREncoded();
        this.isConstructed = explicit;
        this.tag = tag;
        if (explicit) {
            this.octets = data;
            return;
        }
        int lenBytes = getLengthOfLength(data);
        byte[] tmp = new byte[(data.length - lenBytes)];
        System.arraycopy(data, lenBytes, tmp, 0, tmp.length);
        this.octets = tmp;
    }

    public DERApplicationSpecific(int tagNo, ASN1EncodableVector vec) {
        this.tag = tagNo;
        this.isConstructed = true;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        int i = 0;
        while (i != vec.size()) {
            try {
                bOut.write(((ASN1Encodable) vec.get(i)).getEncoded());
                i++;
            } catch (IOException e) {
                throw new ASN1ParsingException("malformed object: " + e, e);
            }
        }
        this.octets = bOut.toByteArray();
    }

    private int getLengthOfLength(byte[] data) {
        int count = 2;
        while ((data[count - 1] & 128) != 0) {
            count++;
        }
        return count;
    }

    public boolean isConstructed() {
        return this.isConstructed;
    }

    public byte[] getContents() {
        return this.octets;
    }

    public int getApplicationTag() {
        return this.tag;
    }

    public DERObject getObject() throws IOException {
        return new ASN1InputStream(getContents()).readObject();
    }

    public DERObject getObject(int derTagNo) throws IOException {
        if (derTagNo >= 31) {
            throw new IOException("unsupported tag number");
        }
        byte[] orig = getEncoded();
        byte[] tmp = replaceTagNumber(derTagNo, orig);
        if ((orig[0] & 32) != 0) {
            tmp[0] = (byte) (tmp[0] | 32);
        }
        return new ASN1InputStream(tmp).readObject();
    }

    void encode(DEROutputStream out) throws IOException {
        int classBits = 64;
        if (this.isConstructed) {
            classBits = 64 | 32;
        }
        out.writeEncoded(classBits, this.tag, this.octets);
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof DERApplicationSpecific)) {
            return false;
        }
        DERApplicationSpecific other = (DERApplicationSpecific) o;
        if (this.isConstructed == other.isConstructed && this.tag == other.tag && Arrays.areEqual(this.octets, other.octets)) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return ((this.isConstructed ? 1 : 0) ^ this.tag) ^ Arrays.hashCode(this.octets);
    }

    private byte[] replaceTagNumber(int newTag, byte[] input) throws IOException {
        int index = 1;
        if ((input[0] & 31) == 31) {
            int tagNo = 0;
            int index2 = 1 + 1;
            int b = input[1] & 255;
            if ((b & CertificateBody.profileType) == 0) {
                throw new ASN1ParsingException("corrupted stream - invalid high tag number found");
            }
            while (b >= 0 && (b & 128) != 0) {
                tagNo = (tagNo | (b & CertificateBody.profileType)) << 7;
                b = input[index2] & 255;
                index2++;
            }
            tagNo |= b & CertificateBody.profileType;
            index = index2;
        }
        byte[] tmp = new byte[((input.length - index) + 1)];
        System.arraycopy(input, index, tmp, 1, tmp.length - 1);
        tmp[0] = (byte) newTag;
        return tmp;
    }
}
