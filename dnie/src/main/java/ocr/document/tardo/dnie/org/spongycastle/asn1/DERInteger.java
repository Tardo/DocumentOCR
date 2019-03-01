package org.spongycastle.asn1;

import java.io.IOException;
import java.math.BigInteger;
import org.spongycastle.util.Arrays;

public class DERInteger extends ASN1Object {
    byte[] bytes;

    public static DERInteger getInstance(Object obj) {
        if (obj == null || (obj instanceof DERInteger)) {
            return (DERInteger) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERInteger getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERInteger)) {
            return getInstance(o);
        }
        return new ASN1Integer(ASN1OctetString.getInstance(obj.getObject()).getOctets());
    }

    public DERInteger(int value) {
        this.bytes = BigInteger.valueOf((long) value).toByteArray();
    }

    public DERInteger(BigInteger value) {
        this.bytes = value.toByteArray();
    }

    public DERInteger(byte[] bytes) {
        this.bytes = bytes;
    }

    public BigInteger getValue() {
        return new BigInteger(this.bytes);
    }

    public BigInteger getPositiveValue() {
        return new BigInteger(1, this.bytes);
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(2, this.bytes);
    }

    public int hashCode() {
        int value = 0;
        for (int i = 0; i != this.bytes.length; i++) {
            value ^= (this.bytes[i] & 255) << (i % 4);
        }
        return value;
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof DERInteger)) {
            return false;
        }
        return Arrays.areEqual(this.bytes, ((DERInteger) o).bytes);
    }

    public String toString() {
        return getValue().toString();
    }
}
