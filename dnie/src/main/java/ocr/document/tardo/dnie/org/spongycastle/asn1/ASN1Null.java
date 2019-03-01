package org.spongycastle.asn1;

import java.io.IOException;

public abstract class ASN1Null extends ASN1Object {
    abstract void encode(DEROutputStream dEROutputStream) throws IOException;

    public int hashCode() {
        return -1;
    }

    boolean asn1Equals(DERObject o) {
        if (o instanceof ASN1Null) {
            return true;
        }
        return false;
    }

    public String toString() {
        return "NULL";
    }
}
