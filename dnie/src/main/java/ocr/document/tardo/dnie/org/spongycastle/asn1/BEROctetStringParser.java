package org.spongycastle.asn1;

import java.io.IOException;
import java.io.InputStream;
import org.spongycastle.util.io.Streams;

public class BEROctetStringParser implements ASN1OctetStringParser {
    private ASN1StreamParser _parser;

    BEROctetStringParser(ASN1StreamParser parser) {
        this._parser = parser;
    }

    public InputStream getOctetStream() {
        return new ConstructedOctetStream(this._parser);
    }

    public DERObject getLoadedObject() throws IOException {
        return new BERConstructedOctetString(Streams.readAll(getOctetStream()));
    }

    public DERObject getDERObject() {
        try {
            return getLoadedObject();
        } catch (IOException e) {
            throw new ASN1ParsingException("IOException converting stream to byte array: " + e.getMessage(), e);
        }
    }
}