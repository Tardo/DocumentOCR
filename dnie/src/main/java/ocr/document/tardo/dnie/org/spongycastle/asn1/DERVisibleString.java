package org.spongycastle.asn1;

import java.io.IOException;

public class DERVisibleString extends ASN1Object implements DERString {
    String string;

    public static DERVisibleString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERVisibleString)) {
            return (DERVisibleString) obj;
        }
        if (obj instanceof ASN1OctetString) {
            return new DERVisibleString(((ASN1OctetString) obj).getOctets());
        }
        if (obj instanceof ASN1TaggedObject) {
            return getInstance(((ASN1TaggedObject) obj).getObject());
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERVisibleString getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    public DERVisibleString(byte[] string) {
        char[] cs = new char[string.length];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char) (string[i] & 255);
        }
        this.string = new String(cs);
    }

    public DERVisibleString(String string) {
        this.string = string;
    }

    public String getString() {
        return this.string;
    }

    public String toString() {
        return this.string;
    }

    public byte[] getOctets() {
        char[] cs = this.string.toCharArray();
        byte[] bs = new byte[cs.length];
        for (int i = 0; i != cs.length; i++) {
            bs[i] = (byte) cs[i];
        }
        return bs;
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(26, getOctets());
    }

    boolean asn1Equals(DERObject o) {
        if (o instanceof DERVisibleString) {
            return getString().equals(((DERVisibleString) o).getString());
        }
        return false;
    }

    public int hashCode() {
        return getString().hashCode();
    }
}
