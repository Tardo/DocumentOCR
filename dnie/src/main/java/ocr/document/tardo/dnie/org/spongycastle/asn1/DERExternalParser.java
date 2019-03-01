package org.spongycastle.asn1;

import java.io.IOException;

public class DERExternalParser implements DEREncodable, InMemoryRepresentable {
    private ASN1StreamParser _parser;

    public DERExternalParser(ASN1StreamParser parser) {
        this._parser = parser;
    }

    public DEREncodable readObject() throws IOException {
        return this._parser.readObject();
    }

    public DERObject getLoadedObject() throws IOException {
        try {
            return new DERExternal(this._parser.readVector());
        } catch (IllegalArgumentException e) {
            throw new ASN1Exception(e.getMessage(), e);
        }
    }

    public DERObject getDERObject() {
        try {
            return getLoadedObject();
        } catch (IOException ioe) {
            throw new ASN1ParsingException("unable to get DER object", ioe);
        } catch (IllegalArgumentException ioe2) {
            throw new ASN1ParsingException("unable to get DER object", ioe2);
        }
    }
}