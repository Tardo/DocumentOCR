package org.spongycastle.asn1.cms;

import java.io.IOException;
import org.spongycastle.asn1.ASN1SequenceParser;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class CompressedDataParser {
    private AlgorithmIdentifier _compressionAlgorithm;
    private ContentInfoParser _encapContentInfo;
    private DERInteger _version;

    public CompressedDataParser(ASN1SequenceParser seq) throws IOException {
        this._version = (DERInteger) seq.readObject();
        this._compressionAlgorithm = AlgorithmIdentifier.getInstance(seq.readObject().getDERObject());
        this._encapContentInfo = new ContentInfoParser((ASN1SequenceParser) seq.readObject());
    }

    public DERInteger getVersion() {
        return this._version;
    }

    public AlgorithmIdentifier getCompressionAlgorithmIdentifier() {
        return this._compressionAlgorithm;
    }

    public ContentInfoParser getEncapContentInfo() {
        return this._encapContentInfo;
    }
}
