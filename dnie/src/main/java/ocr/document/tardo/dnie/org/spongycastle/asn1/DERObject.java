package org.spongycastle.asn1;

import java.io.IOException;

public abstract class DERObject extends ASN1Encodable implements DERTags {
    abstract void encode(DEROutputStream dEROutputStream) throws IOException;

    public abstract boolean equals(Object obj);

    public abstract int hashCode();

    public DERObject toASN1Object() {
        return this;
    }
}
