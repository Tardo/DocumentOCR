package org.spongycastle.asn1;

import java.io.IOException;
import java.math.BigInteger;
import org.spongycastle.util.Arrays;

public class DEREnumerated extends ASN1Object {
    byte[] bytes;

    public static DEREnumerated getInstance(Object obj) {
        if (obj == null || (obj instanceof DEREnumerated)) {
            return (DEREnumerated) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DEREnumerated getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DEREnumerated)) {
            return getInstance(o);
        }
        return new DEREnumerated(((ASN1OctetString) o).getOctets());
    }

    public DEREnumerated(int value) {
        this.bytes = BigInteger.valueOf((long) value).toByteArray();
    }

    public DEREnumerated(BigInteger value) {
        this.bytes = value.toByteArray();
    }

    public DEREnumerated(byte[] bytes) {
        this.bytes = bytes;
    }

    public BigInteger getValue() {
        return new BigInteger(this.bytes);
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(10, this.bytes);
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof DEREnumerated)) {
            return false;
        }
        return Arrays.areEqual(this.bytes, ((DEREnumerated) o).bytes);
    }

    public int hashCode() {
        return Arrays.hashCode(this.bytes);
    }
}
