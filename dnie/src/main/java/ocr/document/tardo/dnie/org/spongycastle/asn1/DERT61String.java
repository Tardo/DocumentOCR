package org.spongycastle.asn1;

import java.io.IOException;

public class DERT61String extends ASN1Object implements DERString {
    String string;

    public static DERT61String getInstance(Object obj) {
        if (obj == null || (obj instanceof DERT61String)) {
            return (DERT61String) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERT61String getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit) {
            return getInstance(o);
        }
        return new DERT61String(ASN1OctetString.getInstance(o).getOctets());
    }

    public DERT61String(byte[] string) {
        char[] cs = new char[string.length];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char) (string[i] & 255);
        }
        this.string = new String(cs);
    }

    public DERT61String(String string) {
        this.string = string;
    }

    public String getString() {
        return this.string;
    }

    public String toString() {
        return this.string;
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(20, getOctets());
    }

    public byte[] getOctets() {
        char[] cs = this.string.toCharArray();
        byte[] bs = new byte[cs.length];
        for (int i = 0; i != cs.length; i++) {
            bs[i] = (byte) cs[i];
        }
        return bs;
    }

    boolean asn1Equals(DERObject o) {
        if (o instanceof DERT61String) {
            return getString().equals(((DERT61String) o).getString());
        }
        return false;
    }

    public int hashCode() {
        return getString().hashCode();
    }
}
