package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

public class RecipientKeyIdentifier extends ASN1Encodable {
    private DERGeneralizedTime date;
    private OtherKeyAttribute other;
    private ASN1OctetString subjectKeyIdentifier;

    public RecipientKeyIdentifier(ASN1OctetString subjectKeyIdentifier, DERGeneralizedTime date, OtherKeyAttribute other) {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.date = date;
        this.other = other;
    }

    public RecipientKeyIdentifier(byte[] subjectKeyIdentifier, DERGeneralizedTime date, OtherKeyAttribute other) {
        this.subjectKeyIdentifier = new DEROctetString(subjectKeyIdentifier);
        this.date = date;
        this.other = other;
    }

    public RecipientKeyIdentifier(byte[] subjectKeyIdentifier) {
        this(subjectKeyIdentifier, null, null);
    }

    public RecipientKeyIdentifier(ASN1Sequence seq) {
        this.subjectKeyIdentifier = ASN1OctetString.getInstance(seq.getObjectAt(0));
        switch (seq.size()) {
            case 1:
                return;
            case 2:
                if (seq.getObjectAt(1) instanceof DERGeneralizedTime) {
                    this.date = (DERGeneralizedTime) seq.getObjectAt(1);
                    return;
                } else {
                    this.other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
                    return;
                }
            case 3:
                this.date = (DERGeneralizedTime) seq.getObjectAt(1);
                this.other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
                return;
            default:
                throw new IllegalArgumentException("Invalid RecipientKeyIdentifier");
        }
    }

    public static RecipientKeyIdentifier getInstance(ASN1TaggedObject _ato, boolean _explicit) {
        return getInstance(ASN1Sequence.getInstance(_ato, _explicit));
    }

    public static RecipientKeyIdentifier getInstance(Object _obj) {
        if (_obj == null || (_obj instanceof RecipientKeyIdentifier)) {
            return (RecipientKeyIdentifier) _obj;
        }
        if (_obj instanceof ASN1Sequence) {
            return new RecipientKeyIdentifier((ASN1Sequence) _obj);
        }
        throw new IllegalArgumentException("Invalid RecipientKeyIdentifier: " + _obj.getClass().getName());
    }

    public ASN1OctetString getSubjectKeyIdentifier() {
        return this.subjectKeyIdentifier;
    }

    public DERGeneralizedTime getDate() {
        return this.date;
    }

    public OtherKeyAttribute getOtherKeyAttribute() {
        return this.other;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.subjectKeyIdentifier);
        if (this.date != null) {
            v.add(this.date);
        }
        if (this.other != null) {
            v.add(this.other);
        }
        return new DERSequence(v);
    }
}
