package org.spongycastle.asn1.cms;

import java.io.IOException;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1SequenceParser;
import org.spongycastle.asn1.ASN1SetParser;
import org.spongycastle.asn1.ASN1TaggedObjectParser;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;

public class AuthEnvelopedDataParser {
    private DEREncodable nextObject;
    private boolean originatorInfoCalled;
    private ASN1SequenceParser seq;
    private DERInteger version;

    public AuthEnvelopedDataParser(ASN1SequenceParser seq) throws IOException {
        this.seq = seq;
        this.version = (DERInteger) seq.readObject();
    }

    public DERInteger getVersion() {
        return this.version;
    }

    public OriginatorInfo getOriginatorInfo() throws IOException {
        this.originatorInfoCalled = true;
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }
        if (!(this.nextObject instanceof ASN1TaggedObjectParser) || ((ASN1TaggedObjectParser) this.nextObject).getTagNo() != 0) {
            return null;
        }
        ASN1SequenceParser originatorInfo = (ASN1SequenceParser) ((ASN1TaggedObjectParser) this.nextObject).getObjectParser(16, false);
        this.nextObject = null;
        return OriginatorInfo.getInstance(originatorInfo.getDERObject());
    }

    public ASN1SetParser getRecipientInfos() throws IOException {
        if (!this.originatorInfoCalled) {
            getOriginatorInfo();
        }
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }
        ASN1SetParser recipientInfos = this.nextObject;
        this.nextObject = null;
        return recipientInfos;
    }

    public EncryptedContentInfoParser getAuthEncryptedContentInfo() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }
        if (this.nextObject == null) {
            return null;
        }
        ASN1SequenceParser o = this.nextObject;
        this.nextObject = null;
        return new EncryptedContentInfoParser(o);
    }

    public ASN1SetParser getAuthAttrs() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }
        if (!(this.nextObject instanceof ASN1TaggedObjectParser)) {
            return null;
        }
        DEREncodable o = this.nextObject;
        this.nextObject = null;
        return (ASN1SetParser) ((ASN1TaggedObjectParser) o).getObjectParser(17, false);
    }

    public ASN1OctetString getMac() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }
        DEREncodable o = this.nextObject;
        this.nextObject = null;
        return ASN1OctetString.getInstance(o.getDERObject());
    }

    public ASN1SetParser getUnauthAttrs() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }
        if (this.nextObject == null) {
            return null;
        }
        DEREncodable o = this.nextObject;
        this.nextObject = null;
        return (ASN1SetParser) ((ASN1TaggedObjectParser) o).getObjectParser(17, false);
    }
}
