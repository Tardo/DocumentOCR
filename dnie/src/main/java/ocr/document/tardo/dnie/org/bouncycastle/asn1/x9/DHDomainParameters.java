package org.bouncycastle.asn1.x9;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

public class DHDomainParameters extends ASN1Object {
    /* renamed from: g */
    private ASN1Integer f468g;
    /* renamed from: j */
    private ASN1Integer f469j;
    /* renamed from: p */
    private ASN1Integer f470p;
    /* renamed from: q */
    private ASN1Integer f471q;
    private DHValidationParms validationParms;

    public DHDomainParameters(ASN1Integer aSN1Integer, ASN1Integer aSN1Integer2, ASN1Integer aSN1Integer3, ASN1Integer aSN1Integer4, DHValidationParms dHValidationParms) {
        if (aSN1Integer == null) {
            throw new IllegalArgumentException("'p' cannot be null");
        } else if (aSN1Integer2 == null) {
            throw new IllegalArgumentException("'g' cannot be null");
        } else if (aSN1Integer3 == null) {
            throw new IllegalArgumentException("'q' cannot be null");
        } else {
            this.f470p = aSN1Integer;
            this.f468g = aSN1Integer2;
            this.f471q = aSN1Integer3;
            this.f469j = aSN1Integer4;
            this.validationParms = dHValidationParms;
        }
    }

    private DHDomainParameters(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() < 3 || aSN1Sequence.size() > 5) {
            throw new IllegalArgumentException("Bad sequence size: " + aSN1Sequence.size());
        }
        Enumeration objects = aSN1Sequence.getObjects();
        this.f470p = DERInteger.getInstance(objects.nextElement());
        this.f468g = DERInteger.getInstance(objects.nextElement());
        this.f471q = DERInteger.getInstance(objects.nextElement());
        ASN1Encodable next = getNext(objects);
        if (next != null && (next instanceof ASN1Integer)) {
            this.f469j = DERInteger.getInstance(next);
            next = getNext(objects);
        }
        if (next != null) {
            this.validationParms = DHValidationParms.getInstance(next.toASN1Primitive());
        }
    }

    public static DHDomainParameters getInstance(Object obj) {
        if (obj == null || (obj instanceof DHDomainParameters)) {
            return (DHDomainParameters) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new DHDomainParameters((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid DHDomainParameters: " + obj.getClass().getName());
    }

    public static DHDomainParameters getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    private static ASN1Encodable getNext(Enumeration enumeration) {
        return enumeration.hasMoreElements() ? (ASN1Encodable) enumeration.nextElement() : null;
    }

    public ASN1Integer getG() {
        return this.f468g;
    }

    public ASN1Integer getJ() {
        return this.f469j;
    }

    public ASN1Integer getP() {
        return this.f470p;
    }

    public ASN1Integer getQ() {
        return this.f471q;
    }

    public DHValidationParms getValidationParms() {
        return this.validationParms;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(this.f470p);
        aSN1EncodableVector.add(this.f468g);
        aSN1EncodableVector.add(this.f471q);
        if (this.f469j != null) {
            aSN1EncodableVector.add(this.f469j);
        }
        if (this.validationParms != null) {
            aSN1EncodableVector.add(this.validationParms);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}
