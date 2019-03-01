package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

public class RecipientKeyIdentifier extends ASN1Object {
    private DERGeneralizedTime date;
    private OtherKeyAttribute other;
    private ASN1OctetString subjectKeyIdentifier;

    public RecipientKeyIdentifier(ASN1OctetString aSN1OctetString, DERGeneralizedTime dERGeneralizedTime, OtherKeyAttribute otherKeyAttribute) {
        this.subjectKeyIdentifier = aSN1OctetString;
        this.date = dERGeneralizedTime;
        this.other = otherKeyAttribute;
    }

    public RecipientKeyIdentifier(ASN1Sequence aSN1Sequence) {
        this.subjectKeyIdentifier = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(0));
        switch (aSN1Sequence.size()) {
            case 1:
                return;
            case 2:
                if (aSN1Sequence.getObjectAt(1) instanceof DERGeneralizedTime) {
                    this.date = (DERGeneralizedTime) aSN1Sequence.getObjectAt(1);
                    return;
                } else {
                    this.other = OtherKeyAttribute.getInstance(aSN1Sequence.getObjectAt(2));
                    return;
                }
            case 3:
                this.date = (DERGeneralizedTime) aSN1Sequence.getObjectAt(1);
                this.other = OtherKeyAttribute.getInstance(aSN1Sequence.getObjectAt(2));
                return;
            default:
                throw new IllegalArgumentException("Invalid RecipientKeyIdentifier");
        }
    }

    public RecipientKeyIdentifier(byte[] bArr) {
        this(bArr, null, null);
    }

    public RecipientKeyIdentifier(byte[] bArr, DERGeneralizedTime dERGeneralizedTime, OtherKeyAttribute otherKeyAttribute) {
        this.subjectKeyIdentifier = new DEROctetString(bArr);
        this.date = dERGeneralizedTime;
        this.other = otherKeyAttribute;
    }

    public static RecipientKeyIdentifier getInstance(Object obj) {
        if (obj == null || (obj instanceof RecipientKeyIdentifier)) {
            return (RecipientKeyIdentifier) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new RecipientKeyIdentifier((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid RecipientKeyIdentifier: " + obj.getClass().getName());
    }

    public static RecipientKeyIdentifier getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public DERGeneralizedTime getDate() {
        return this.date;
    }

    public OtherKeyAttribute getOtherKeyAttribute() {
        return this.other;
    }

    public ASN1OctetString getSubjectKeyIdentifier() {
        return this.subjectKeyIdentifier;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(this.subjectKeyIdentifier);
        if (this.date != null) {
            aSN1EncodableVector.add(this.date);
        }
        if (this.other != null) {
            aSN1EncodableVector.add(this.other);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}
