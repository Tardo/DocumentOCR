package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.BERTaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;

public class ContentInfo extends ASN1Encodable implements CMSObjectIdentifiers {
    private DEREncodable content;
    private ASN1ObjectIdentifier contentType;

    public static ContentInfo getInstance(Object obj) {
        if (obj == null || (obj instanceof ContentInfo)) {
            return (ContentInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new ContentInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public ContentInfo(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.contentType = (ASN1ObjectIdentifier) seq.getObjectAt(0);
        if (seq.size() > 1) {
            ASN1TaggedObject tagged = (ASN1TaggedObject) seq.getObjectAt(1);
            if (tagged.isExplicit() && tagged.getTagNo() == 0) {
                this.content = tagged.getObject();
                return;
            }
            throw new IllegalArgumentException("Bad tag for 'content'");
        }
    }

    public ContentInfo(ASN1ObjectIdentifier contentType, DEREncodable content) {
        this.contentType = contentType;
        this.content = content;
    }

    public ASN1ObjectIdentifier getContentType() {
        return this.contentType;
    }

    public DEREncodable getContent() {
        return this.content;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.contentType);
        if (this.content != null) {
            v.add(new BERTaggedObject(0, this.content));
        }
        return new BERSequence(v);
    }
}
