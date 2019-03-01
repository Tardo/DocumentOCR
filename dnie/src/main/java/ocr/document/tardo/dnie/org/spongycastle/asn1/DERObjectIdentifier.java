package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import org.bouncycastle.asn1.eac.CertificateBody;

public class DERObjectIdentifier extends ASN1Object {
    String identifier;

    public static DERObjectIdentifier getInstance(Object obj) {
        if (obj == null || (obj instanceof DERObjectIdentifier)) {
            return (DERObjectIdentifier) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERObjectIdentifier getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERObjectIdentifier)) {
            return getInstance(o);
        }
        return new ASN1ObjectIdentifier(ASN1OctetString.getInstance(obj.getObject()).getOctets());
    }

    DERObjectIdentifier(byte[] bytes) {
        StringBuffer objId = new StringBuffer();
        long value = 0;
        BigInteger bigValue = null;
        boolean first = true;
        for (int i = 0; i != bytes.length; i++) {
            int b = bytes[i] & 255;
            if (value < 36028797018963968L) {
                value = (128 * value) + ((long) (b & CertificateBody.profileType));
                if ((b & 128) == 0) {
                    if (first) {
                        switch (((int) value) / 40) {
                            case 0:
                                objId.append('0');
                                break;
                            case 1:
                                objId.append('1');
                                value -= 40;
                                break;
                            default:
                                objId.append('2');
                                value -= 80;
                                break;
                        }
                        first = false;
                    }
                    objId.append('.');
                    objId.append(value);
                    value = 0;
                }
            } else {
                if (bigValue == null) {
                    bigValue = BigInteger.valueOf(value);
                }
                bigValue = bigValue.shiftLeft(7).or(BigInteger.valueOf((long) (b & CertificateBody.profileType)));
                if ((b & 128) == 0) {
                    objId.append('.');
                    objId.append(bigValue);
                    bigValue = null;
                    value = 0;
                }
            }
        }
        this.identifier = objId.toString();
    }

    public DERObjectIdentifier(String identifier) {
        if (isValidIdentifier(identifier)) {
            this.identifier = identifier;
            return;
        }
        throw new IllegalArgumentException("string " + identifier + " not an OID");
    }

    public String getId() {
        return this.identifier;
    }

    private void writeField(OutputStream out, long fieldValue) throws IOException {
        byte[] result = new byte[9];
        int pos = 8;
        result[8] = (byte) (((int) fieldValue) & CertificateBody.profileType);
        while (fieldValue >= 128) {
            fieldValue >>= 7;
            pos--;
            result[pos] = (byte) ((((int) fieldValue) & CertificateBody.profileType) | 128);
        }
        out.write(result, pos, 9 - pos);
    }

    private void writeField(OutputStream out, BigInteger fieldValue) throws IOException {
        int byteCount = (fieldValue.bitLength() + 6) / 7;
        if (byteCount == 0) {
            out.write(0);
            return;
        }
        BigInteger tmpValue = fieldValue;
        byte[] tmp = new byte[byteCount];
        for (int i = byteCount - 1; i >= 0; i--) {
            tmp[i] = (byte) ((tmpValue.intValue() & CertificateBody.profileType) | 128);
            tmpValue = tmpValue.shiftRight(7);
        }
        int i2 = byteCount - 1;
        tmp[i2] = (byte) (tmp[i2] & CertificateBody.profileType);
        out.write(tmp);
    }

    void encode(DEROutputStream out) throws IOException {
        OIDTokenizer tok = new OIDTokenizer(this.identifier);
        OutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        writeField(bOut, (long) ((Integer.parseInt(tok.nextToken()) * 40) + Integer.parseInt(tok.nextToken())));
        while (tok.hasMoreTokens()) {
            String token = tok.nextToken();
            if (token.length() < 18) {
                writeField(bOut, Long.parseLong(token));
            } else {
                writeField(bOut, new BigInteger(token));
            }
        }
        dOut.close();
        out.writeEncoded(6, bOut.toByteArray());
    }

    public int hashCode() {
        return this.identifier.hashCode();
    }

    boolean asn1Equals(DERObject o) {
        if (o instanceof DERObjectIdentifier) {
            return this.identifier.equals(((DERObjectIdentifier) o).identifier);
        }
        return false;
    }

    public String toString() {
        return getId();
    }

    private static boolean isValidIdentifier(String identifier) {
        if (identifier.length() < 3 || identifier.charAt(1) != '.') {
            return false;
        }
        char first = identifier.charAt(0);
        if (first < '0' || first > '2') {
            return false;
        }
        boolean periodAllowed = false;
        for (int i = identifier.length() - 1; i >= 2; i--) {
            char ch = identifier.charAt(i);
            if ('0' <= ch && ch <= '9') {
                periodAllowed = true;
            } else if (ch != '.') {
                return false;
            } else {
                if (!periodAllowed) {
                    return false;
                }
                periodAllowed = false;
            }
        }
        return periodAllowed;
    }
}
