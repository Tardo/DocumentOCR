package org.spongycastle.asn1;

import java.io.IOException;

public class DERBoolean extends ASN1Object {
    public static final DERBoolean FALSE = new DERBoolean(false);
    public static final DERBoolean TRUE = new DERBoolean(true);
    byte value;

    public static DERBoolean getInstance(Object obj) {
        if (obj == null || (obj instanceof DERBoolean)) {
            return (DERBoolean) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERBoolean getInstance(boolean value) {
        return value ? TRUE : FALSE;
    }

    public static DERBoolean getInstance(ASN1TaggedObject obj, boolean explicit) {
        Object o = obj.getObject();
        if (explicit || (o instanceof DERBoolean)) {
            return getInstance(o);
        }
        return new DERBoolean(((ASN1OctetString) o).getOctets());
    }

    public DERBoolean(byte[] value) {
        if (value.length != 1) {
            throw new IllegalArgumentException("byte value should have 1 byte in it");
        }
        this.value = value[0];
    }

    public DERBoolean(boolean value) {
        this.value = value ? (byte) -1 : (byte) 0;
    }

    public boolean isTrue() {
        return this.value != (byte) 0;
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(1, new byte[]{this.value});
    }

    protected boolean asn1Equals(DERObject o) {
        if (o != null && (o instanceof DERBoolean) && this.value == ((DERBoolean) o).value) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return this.value;
    }

    public String toString() {
        return this.value != (byte) 0 ? "TRUE" : "FALSE";
    }
}
