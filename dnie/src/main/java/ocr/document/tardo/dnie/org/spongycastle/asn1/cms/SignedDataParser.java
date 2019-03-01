package org.spongycastle.asn1.cms;

import java.io.IOException;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1SequenceParser;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.ASN1SetParser;
import org.spongycastle.asn1.ASN1TaggedObjectParser;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;

public class SignedDataParser {
    private boolean _certsCalled;
    private boolean _crlsCalled;
    private Object _nextObject;
    private ASN1SequenceParser _seq;
    private DERInteger _version;

    public static SignedDataParser getInstance(Object o) throws IOException {
        if (o instanceof ASN1Sequence) {
            return new SignedDataParser(((ASN1Sequence) o).parser());
        }
        if (o instanceof ASN1SequenceParser) {
            return new SignedDataParser((ASN1SequenceParser) o);
        }
        throw new IOException("unknown object encountered: " + o.getClass().getName());
    }

    private SignedDataParser(ASN1SequenceParser seq) throws IOException {
        this._seq = seq;
        this._version = (DERInteger) seq.readObject();
    }

    public DERInteger getVersion() {
        return this._version;
    }

    public ASN1SetParser getDigestAlgorithms() throws IOException {
        DEREncodable o = this._seq.readObject();
        if (o instanceof ASN1Set) {
            return ((ASN1Set) o).parser();
        }
        return (ASN1SetParser) o;
    }

    public ContentInfoParser getEncapContentInfo() throws IOException {
        return new ContentInfoParser((ASN1SequenceParser) this._seq.readObject());
    }

    public ASN1SetParser getCertificates() throws IOException {
        this._certsCalled = true;
        this._nextObject = this._seq.readObject();
        if (!(this._nextObject instanceof ASN1TaggedObjectParser) || ((ASN1TaggedObjectParser) this._nextObject).getTagNo() != 0) {
            return null;
        }
        ASN1SetParser certs = (ASN1SetParser) ((ASN1TaggedObjectParser) this._nextObject).getObjectParser(17, false);
        this._nextObject = null;
        return certs;
    }

    public ASN1SetParser getCrls() throws IOException {
        if (this._certsCalled) {
            this._crlsCalled = true;
            if (this._nextObject == null) {
                this._nextObject = this._seq.readObject();
            }
            if (!(this._nextObject instanceof ASN1TaggedObjectParser) || ((ASN1TaggedObjectParser) this._nextObject).getTagNo() != 1) {
                return null;
            }
            ASN1SetParser crls = (ASN1SetParser) ((ASN1TaggedObjectParser) this._nextObject).getObjectParser(17, false);
            this._nextObject = null;
            return crls;
        }
        throw new IOException("getCerts() has not been called.");
    }

    public ASN1SetParser getSignerInfos() throws IOException {
        if (this._certsCalled && this._crlsCalled) {
            if (this._nextObject == null) {
                this._nextObject = this._seq.readObject();
            }
            return (ASN1SetParser) this._nextObject;
        }
        throw new IOException("getCerts() and/or getCrls() has not been called.");
    }
}
