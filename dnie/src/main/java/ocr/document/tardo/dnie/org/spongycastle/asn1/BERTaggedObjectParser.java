package org.spongycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

public class BERTaggedObjectParser implements ASN1TaggedObjectParser {
    private boolean _constructed;
    private ASN1StreamParser _parser;
    private int _tagNumber;

    protected BERTaggedObjectParser(int baseTag, int tagNumber, InputStream contentStream) {
        this((baseTag & 32) != 0, tagNumber, new ASN1StreamParser(contentStream));
    }

    BERTaggedObjectParser(boolean constructed, int tagNumber, ASN1StreamParser parser) {
        this._constructed = constructed;
        this._tagNumber = tagNumber;
        this._parser = parser;
    }

    public boolean isConstructed() {
        return this._constructed;
    }

    public int getTagNo() {
        return this._tagNumber;
    }

    public DEREncodable getObjectParser(int tag, boolean isExplicit) throws IOException {
        if (!isExplicit) {
            return this._parser.readImplicit(this._constructed, tag);
        }
        if (this._constructed) {
            return this._parser.readObject();
        }
        throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
    }

    public DERObject getLoadedObject() throws IOException {
        return this._parser.readTaggedObject(this._constructed, this._tagNumber);
    }

    public DERObject getDERObject() {
        try {
            return getLoadedObject();
        } catch (IOException e) {
            throw new ASN1ParsingException(e.getMessage());
        }
    }
}
