package org.spongycastle.asn1;

import java.io.IOException;

public class DERGeneralString extends ASN1Object implements DERString {
    private String string;

    public static DERGeneralString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERGeneralString)) {
            return (DERGeneralString) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERGeneralString getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERGeneralString)) {
            return getInstance(o);
        }
        return new DERGeneralString(((ASN1OctetString) o).getOctets());
    }

    public DERGeneralString(byte[] string) {
        char[] cs = new char[string.length];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char) (string[i] & 255);
        }
        this.string = new String(cs);
    }

    public DERGeneralString(String string) {
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
        out.writeEncoded(27, getOctets());
    }

    public int hashCode() {
        return getString().hashCode();
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof DERGeneralString)) {
            return false;
        }
        return getString().equals(((DERGeneralString) o).getString());
    }
}
