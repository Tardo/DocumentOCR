package org.spongycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

public class DEROctetStringParser implements ASN1OctetStringParser {
    private DefiniteLengthInputStream stream;

    DEROctetStringParser(DefiniteLengthInputStream stream) {
        this.stream = stream;
    }

    public InputStream getOctetStream() {
        return this.stream;
    }

    public DERObject getLoadedObject() throws IOException {
        return new DEROctetString(this.stream.toByteArray());
    }

    public DERObject getDERObject() {
        try {
            return getLoadedObject();
        } catch (IOException e) {
            throw new ASN1ParsingException("IOException converting stream to byte array: " + e.getMessage(), e);
        }
    }
}
