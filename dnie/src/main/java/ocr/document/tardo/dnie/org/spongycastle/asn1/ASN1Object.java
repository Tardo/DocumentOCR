package org.spongycastle.asn1;

import java.io.IOException;

public abstract class ASN1Object extends DERObject {
    abstract boolean asn1Equals(DERObject dERObject);

    abstract void encode(DEROutputStream dEROutputStream) throws IOException;

    public abstract int hashCode();

    public static ASN1Object fromByteArray(byte[] data) throws IOException {
        try {
            return (ASN1Object) new ASN1InputStream(data).readObject();
        } catch (ClassCastException e) {
            throw new IOException("cannot recognise object in stream");
        }
    }

    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if ((o instanceof DEREncodable) && asn1Equals(((DEREncodable) o).getDERObject())) {
            return true;
        }
        return false;
    }
}
