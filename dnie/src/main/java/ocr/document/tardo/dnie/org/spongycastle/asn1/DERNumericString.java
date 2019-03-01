package org.spongycastle.asn1;

import java.io.IOException;

public class DERNumericString extends ASN1Object implements DERString {
    String string;

    public static DERNumericString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERNumericString)) {
            return (DERNumericString) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERNumericString getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERNumericString)) {
            return getInstance(o);
        }
        return new DERNumericString(ASN1OctetString.getInstance(o).getOctets());
    }

    public DERNumericString(byte[] string) {
        char[] cs = new char[string.length];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char) (string[i] & 255);
        }
        this.string = new String(cs);
    }

    public DERNumericString(String string) {
        this(string, false);
    }

    public DERNumericString(String string, boolean validate) {
        if (!validate || isNumericString(string)) {
            this.string = string;
            return;
        }
        throw new IllegalArgumentException("string contains illegal characters");
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
        out.writeEncoded(18, getOctets());
    }

    public int hashCode() {
        return getString().hashCode();
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof DERNumericString)) {
            return false;
        }
        return getString().equals(((DERNumericString) o).getString());
    }

    public static boolean isNumericString(String str) {
        for (int i = str.length() - 1; i >= 0; i--) {
            char ch = str.charAt(i);
            if (ch > '') {
                return false;
            }
            if (('0' > ch || ch > '9') && ch != ' ') {
                return false;
            }
        }
        return true;
    }
}
