package org.spongycastle.asn1;

import java.io.IOException;

public interface ASN1TaggedObjectParser extends DEREncodable, InMemoryRepresentable {
    DEREncodable getObjectParser(int i, boolean z) throws IOException;

    int getTagNo();
}
