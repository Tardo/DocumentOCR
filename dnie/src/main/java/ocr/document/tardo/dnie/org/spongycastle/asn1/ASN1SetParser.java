package org.spongycastle.asn1;

import java.io.IOException;

public interface ASN1SetParser extends DEREncodable, InMemoryRepresentable {
    DEREncodable readObject() throws IOException;
}
