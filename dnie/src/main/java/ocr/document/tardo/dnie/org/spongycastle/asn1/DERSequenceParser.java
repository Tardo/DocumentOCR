package org.spongycastle.asn1;

import java.io.IOException;

public class DERSequenceParser implements ASN1SequenceParser {
    private ASN1StreamParser _parser;

    DERSequenceParser(ASN1StreamParser parser) {
        this._parser = parser;
    }

    public DEREncodable readObject() throws IOException {
        return this._parser.readObject();
    }

    public DERObject getLoadedObject() throws IOException {
        return new DERSequence(this._parser.readVector());
    }

    public DERObject getDERObject() {
        try {
            return getLoadedObject();
        } catch (IOException e) {
            throw new IllegalStateException(e.getMessage());
        }
    }
}
