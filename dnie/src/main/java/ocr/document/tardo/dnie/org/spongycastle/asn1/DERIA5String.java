package org.spongycastle.asn1;

import java.io.IOException;

public class DERIA5String extends ASN1Object implements DERString {
    String string;

    public static DERIA5String getInstance(Object obj) {
        if (obj == null || (obj instanceof DERIA5String)) {
            return (DERIA5String) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERIA5String getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERIA5String)) {
            return getInstance(o);
        }
        return new DERIA5String(((ASN1OctetString) o).getOctets());
    }

    public DERIA5String(byte[] string) {
        char[] cs = new char[string.length];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char) (string[i] & 255);
        }
        this.string = new String(cs);
    }

    public DERIA5String(String string) {
        this(string, false);
    }

    public DERIA5String(String string, boolean validate) {
        if (string == null) {
            throw new NullPointerException("string cannot be null");
        } else if (!validate || isIA5String(string)) {
            this.string = string;
        } else {
            throw new IllegalArgumentException("string contains illegal characters");
        }
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
        out.writeEncoded(22, getOctets());
    }

    public int hashCode() {
        return getString().hashCode();
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof DERIA5String)) {
            return false;
        }
        return getString().equals(((DERIA5String) o).getString());
    }

    public static boolean isIA5String(String str) {
        for (int i = str.length() - 1; i >= 0; i--) {
            if (str.charAt(i) > '') {
                return false;
            }
        }
        return true;
    }
}
