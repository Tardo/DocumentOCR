package org.spongycastle.asn1.pkcs;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.BERTaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERTaggedObject;

public class ContentInfo extends ASN1Encodable implements PKCSObjectIdentifiers {
    private DEREncodable content;
    private DERObjectIdentifier contentType;

    public static ContentInfo getInstance(Object obj) {
        if (obj instanceof ContentInfo) {
            return (ContentInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new ContentInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public ContentInfo(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.contentType = (DERObjectIdentifier) e.nextElement();
        if (e.hasMoreElements()) {
            this.content = ((DERTaggedObject) e.nextElement()).getObject();
        }
    }

    public ContentInfo(DERObjectIdentifier contentType, DEREncodable content) {
        this.contentType = contentType;
        this.content = content;
    }

    public DERObjectIdentifier getContentType() {
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