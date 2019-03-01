package org.bouncycastle.asn1.pkcs;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

public class DHParameter extends ASN1Object {
    /* renamed from: g */
    ASN1Integer f449g;
    /* renamed from: l */
    ASN1Integer f450l;
    /* renamed from: p */
    ASN1Integer f451p;

    public DHParameter(BigInteger bigInteger, BigInteger bigInteger2, int i) {
        this.f451p = new ASN1Integer(bigInteger);
        this.f449g = new ASN1Integer(bigInteger2);
        if (i != 0) {
            this.f450l = new ASN1Integer((long) i);
        } else {
            this.f450l = null;
        }
    }

    private DHParameter(ASN1Sequence aSN1Sequence) {
        Enumeration objects = aSN1Sequence.getObjects();
        this.f451p = DERInteger.getInstance(objects.nextElement());
        this.f449g = DERInteger.getInstance(objects.nextElement());
        if (objects.hasMoreElements()) {
            this.f450l = (ASN1Integer) objects.nextElement();
        } else {
            this.f450l = null;
        }
    }

    public static DHParameter getInstance(Object obj) {
        return obj instanceof DHParameter ? (DHParameter) obj : obj != null ? new DHParameter(ASN1Sequence.getInstance(obj)) : null;
    }

    public BigInteger getG() {
        return this.f449g.getPositiveValue();
    }

    public BigInteger getL() {
        return this.f450l == null ? null : this.f450l.getPositiveValue();
    }

    public BigInteger getP() {
        return this.f451p.getPositiveValue();
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(this.f451p);
        aSN1EncodableVector.add(this.f449g);
        if (getL() != null) {
            aSN1EncodableVector.add(this.f450l);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}
