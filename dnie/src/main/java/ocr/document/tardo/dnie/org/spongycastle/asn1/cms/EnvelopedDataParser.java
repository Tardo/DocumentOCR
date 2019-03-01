package org.spongycastle.asn1.cms;

import java.io.IOException;
import org.spongycastle.asn1.ASN1SequenceParser;
import org.spongycastle.asn1.ASN1SetParser;
import org.spongycastle.asn1.ASN1TaggedObjectParser;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;

public class EnvelopedDataParser {
    private DEREncodable _nextObject;
    private boolean _originatorInfoCalled;
    private ASN1SequenceParser _seq;
    private DERInteger _version;

    public EnvelopedDataParser(ASN1SequenceParser seq) throws IOException {
        this._seq = seq;
        this._version = (DERInteger) seq.readObject();
    }

    public DERInteger getVersion() {
        return this._version;
    }

    public OriginatorInfo getOriginatorInfo() throws IOException {
        this._originatorInfoCalled = true;
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }
        if (!(this._nextObject instanceof ASN1TaggedObjectParser) || ((ASN1TaggedObjectParser) this._nextObject).getTagNo() != 0) {
            return null;
        }
        ASN1SequenceParser originatorInfo = (ASN1SequenceParser) ((ASN1TaggedObjectParser) this._nextObject).getObjectParser(16, false);
        this._nextObject = null;
        return OriginatorInfo.getInstance(originatorInfo.getDERObject());
    }

    public ASN1SetParser getRecipientInfos() throws IOException {
        if (!this._originatorInfoCalled) {
            getOriginatorInfo();
        }
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }
        ASN1SetParser recipientInfos = this._nextObject;
        this._nextObject = null;
        return recipientInfos;
    }

    public EncryptedContentInfoParser getEncryptedContentInfo() throws IOException {
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }
        if (this._nextObject == null) {
            return null;
        }
        ASN1SequenceParser o = this._nextObject;
        this._nextObject = null;
        return new EncryptedContentInfoParser(o);
    }

    public ASN1SetParser getUnprotectedAttrs() throws IOException {
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }
        if (this._nextObject == null) {
            return null;
        }
        DEREncodable o = this._nextObject;
        this._nextObject = null;
        return (ASN1SetParser) ((ASN1TaggedObjectParser) o).getObjectParser(17, false);
    }
}
