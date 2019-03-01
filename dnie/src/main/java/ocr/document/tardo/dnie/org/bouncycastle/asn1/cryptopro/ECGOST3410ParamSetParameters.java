package org.bouncycastle.asn1.cryptopro;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class ECGOST3410ParamSetParameters extends ASN1Object {
    /* renamed from: a */
    ASN1Integer f438a;
    /* renamed from: b */
    ASN1Integer f439b;
    /* renamed from: p */
    ASN1Integer f440p;
    /* renamed from: q */
    ASN1Integer f441q;
    /* renamed from: x */
    ASN1Integer f442x;
    /* renamed from: y */
    ASN1Integer f443y;

    public ECGOST3410ParamSetParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, int i, BigInteger bigInteger5) {
        this.f438a = new ASN1Integer(bigInteger);
        this.f439b = new ASN1Integer(bigInteger2);
        this.f440p = new ASN1Integer(bigInteger3);
        this.f441q = new ASN1Integer(bigInteger4);
        this.f442x = new ASN1Integer((long) i);
        this.f443y = new ASN1Integer(bigInteger5);
    }

    public ECGOST3410ParamSetParameters(ASN1Sequence aSN1Sequence) {
        Enumeration objects = aSN1Sequence.getObjects();
        this.f438a = (ASN1Integer) objects.nextElement();
        this.f439b = (ASN1Integer) objects.nextElement();
        this.f440p = (ASN1Integer) objects.nextElement();
        this.f441q = (ASN1Integer) objects.nextElement();
        this.f442x = (ASN1Integer) objects.nextElement();
        this.f443y = (ASN1Integer) objects.nextElement();
    }

    public static ECGOST3410ParamSetParameters getInstance(Object obj) {
        if (obj == null || (obj instanceof ECGOST3410ParamSetParameters)) {
            return (ECGOST3410ParamSetParameters) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new ECGOST3410ParamSetParameters((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid GOST3410Parameter: " + obj.getClass().getName());
    }

    public static ECGOST3410ParamSetParameters getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public BigInteger getA() {
        return this.f438a.getPositiveValue();
    }

    public BigInteger getP() {
        return this.f440p.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.f441q.getPositiveValue();
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(this.f438a);
        aSN1EncodableVector.add(this.f439b);
        aSN1EncodableVector.add(this.f440p);
        aSN1EncodableVector.add(this.f441q);
        aSN1EncodableVector.add(this.f442x);
        aSN1EncodableVector.add(this.f443y);
        return new DERSequence(aSN1EncodableVector);
    }
}
