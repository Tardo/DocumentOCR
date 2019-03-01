package org.spongycastle.asn1.cms;

import java.io.IOException;
import org.spongycastle.asn1.ASN1SequenceParser;
import org.spongycastle.asn1.ASN1TaggedObjectParser;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class EncryptedContentInfoParser {
    private AlgorithmIdentifier _contentEncryptionAlgorithm;
    private DERObjectIdentifier _contentType;
    private ASN1TaggedObjectParser _encryptedContent;

    public EncryptedContentInfoParser(ASN1SequenceParser seq) throws IOException {
        this._contentType = (DERObjectIdentifier) seq.readObject();
        this._contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.readObject().getDERObject());
        this._encryptedContent = (ASN1TaggedObjectParser) seq.readObject();
    }

    public DERObjectIdentifier getContentType() {
        return this._contentType;
    }

    public AlgorithmIdentifier getContentEncryptionAlgorithm() {
        return this._contentEncryptionAlgorithm;
    }

    public DEREncodable getEncryptedContent(int tag) throws IOException {
        return this._encryptedContent.getObjectParser(tag, false);
    }
}
