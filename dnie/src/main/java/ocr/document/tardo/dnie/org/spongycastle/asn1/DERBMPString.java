package org.spongycastle.asn1;

import java.io.IOException;

public class DERBMPString extends ASN1Object implements DERString {
    String string;

    public static DERBMPString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERBMPString)) {
            return (DERBMPString) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERBMPString getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERBMPString)) {
            return getInstance(o);
        }
        return new DERBMPString(ASN1OctetString.getInstance(o).getOctets());
    }

    public DERBMPString(byte[] string) {
        char[] cs = new char[(string.length / 2)];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char) ((string[i * 2] << 8) | (string[(i * 2) + 1] & 255));
        }
        this.string = new String(cs);
    }

    public DERBMPString(String string) {
        this.string = string;
    }

    public String getString() {
        return this.string;
    }

    public String toString() {
        return this.string;
    }

    public int hashCode() {
        return getString().hashCode();
    }

    protected boolean asn1Equals(DERObject o) {
        if (!(o instanceof DERBMPString)) {
            return false;
        }
        return getString().equals(((DERBMPString) o).getString());
    }

    void encode(DEROutputStream out) throws IOException {
        char[] c = this.string.toCharArray();
        byte[] b = new byte[(c.length * 2)];
        for (int i = 0; i != c.length; i++) {
            b[i * 2] = (byte) (c[i] >> 8);
            b[(i * 2) + 1] = (byte) c[i];
        }
        out.writeEncoded(30, b);
    }
}
