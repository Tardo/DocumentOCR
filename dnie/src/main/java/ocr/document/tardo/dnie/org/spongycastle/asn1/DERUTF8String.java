package org.spongycastle.asn1;

import java.io.IOException;
import org.spongycastle.util.Strings;

public class DERUTF8String extends ASN1Object implements DERString {
    String string;

    public static DERUTF8String getInstance(Object obj) {
        if (obj == null || (obj instanceof DERUTF8String)) {
            return (DERUTF8String) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERUTF8String getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERUTF8String)) {
            return getInstance(o);
        }
        return new DERUTF8String(ASN1OctetString.getInstance(o).getOctets());
    }

    public DERUTF8String(byte[] string) {
        try {
            this.string = Strings.fromUTF8ByteArray(string);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException("UTF8 encoding invalid");
        }
    }

    public DERUTF8String(String string) {
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

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof DERUTF8String)) {
            return false;
        }
        return getString().equals(((DERUTF8String) o).getString());
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(12, Strings.toUTF8ByteArray(this.string));
    }
}
