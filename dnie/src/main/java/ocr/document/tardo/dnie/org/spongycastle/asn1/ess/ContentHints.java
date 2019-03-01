package org.spongycastle.asn1.ess;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERUTF8String;

public class ContentHints extends ASN1Encodable {
    private DERUTF8String contentDescription;
    private DERObjectIdentifier contentType;

    public static ContentHints getInstance(Object o) {
        if (o == null || (o instanceof ContentHints)) {
            return (ContentHints) o;
        }
        if (o instanceof ASN1Sequence) {
            return new ContentHints((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in 'ContentHints' factory : " + o.getClass().getName() + ".");
    }

    private ContentHints(ASN1Sequence seq) {
        DEREncodable field = seq.getObjectAt(0);
        if (field.getDERObject() instanceof DERUTF8String) {
            this.contentDescription = DERUTF8String.getInstance(field);
            this.contentType = DERObjectIdentifier.getInstance(seq.getObjectAt(1));
            return;
        }
        this.contentType = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
    }

    public ContentHints(DERObjectIdentifier contentType) {
        this.contentType = contentType;
        this.contentDescription = null;
    }

    public ContentHints(DERObjectIdentifier contentType, DERUTF8String contentDescription) {
        this.contentType = contentType;
        this.contentDescription = contentDescription;
    }

    public DERObjectIdentifier getContentType() {
        return this.contentType;
    }

    public DERUTF8String getContentDescription() {
        return this.contentDescription;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.contentDescription != null) {
            v.add(this.contentDescription);
        }
        v.add(this.contentType);
        return new DERSequence(v);
    }
}
