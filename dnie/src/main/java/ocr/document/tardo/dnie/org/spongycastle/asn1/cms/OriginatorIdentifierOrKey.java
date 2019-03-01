package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.SubjectKeyIdentifier;

public class OriginatorIdentifierOrKey extends ASN1Encodable implements ASN1Choice {
    private DEREncodable id;

    public OriginatorIdentifierOrKey(IssuerAndSerialNumber id) {
        this.id = id;
    }

    public OriginatorIdentifierOrKey(ASN1OctetString id) {
        this(new SubjectKeyIdentifier(id));
    }

    public OriginatorIdentifierOrKey(SubjectKeyIdentifier id) {
        this.id = new DERTaggedObject(false, 0, id);
    }

    public OriginatorIdentifierOrKey(OriginatorPublicKey id) {
        this.id = new DERTaggedObject(false, 1, id);
    }

    public OriginatorIdentifierOrKey(DERObject id) {
        this.id = id;
    }

    public static OriginatorIdentifierOrKey getInstance(ASN1TaggedObject o, boolean explicit) {
        if (explicit) {
            return getInstance(o.getObject());
        }
        throw new IllegalArgumentException("Can't implicitly tag OriginatorIdentifierOrKey");
    }

    public static OriginatorIdentifierOrKey getInstance(Object o) {
        if (o == null || (o instanceof OriginatorIdentifierOrKey)) {
            return (OriginatorIdentifierOrKey) o;
        }
        if (o instanceof IssuerAndSerialNumber) {
            return new OriginatorIdentifierOrKey((IssuerAndSerialNumber) o);
        }
        if (o instanceof SubjectKeyIdentifier) {
            return new OriginatorIdentifierOrKey((SubjectKeyIdentifier) o);
        }
        if (o instanceof OriginatorPublicKey) {
            return new OriginatorIdentifierOrKey((OriginatorPublicKey) o);
        }
        if (o instanceof ASN1TaggedObject) {
            return new OriginatorIdentifierOrKey((ASN1TaggedObject) o);
        }
        throw new IllegalArgumentException("Invalid OriginatorIdentifierOrKey: " + o.getClass().getName());
    }

    public DEREncodable getId() {
        return this.id;
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber() {
        if (this.id instanceof IssuerAndSerialNumber) {
            return (IssuerAndSerialNumber) this.id;
        }
        return null;
    }

    public SubjectKeyIdentifier getSubjectKeyIdentifier() {
        if ((this.id instanceof ASN1TaggedObject) && ((ASN1TaggedObject) this.id).getTagNo() == 0) {
            return SubjectKeyIdentifier.getInstance((ASN1TaggedObject) this.id, false);
        }
        return null;
    }

    public OriginatorPublicKey getOriginatorKey() {
        if ((this.id instanceof ASN1TaggedObject) && ((ASN1TaggedObject) this.id).getTagNo() == 1) {
            return OriginatorPublicKey.getInstance((ASN1TaggedObject) this.id, false);
        }
        return null;
    }

    public DERObject toASN1Object() {
        return this.id.getDERObject();
    }
}
