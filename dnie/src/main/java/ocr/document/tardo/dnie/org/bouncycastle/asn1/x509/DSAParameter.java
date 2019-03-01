package org.bouncycastle.asn1.x509;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

public class DSAParameter extends ASN1Object {
    /* renamed from: g */
    ASN1Integer f460g;
    /* renamed from: p */
    ASN1Integer f461p;
    /* renamed from: q */
    ASN1Integer f462q;

    public DSAParameter(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f461p = new ASN1Integer(bigInteger);
        this.f462q = new ASN1Integer(bigInteger2);
        this.f460g = new ASN1Integer(bigInteger3);
    }

    private DSAParameter(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 3) {
            throw new IllegalArgumentException("Bad sequence size: " + aSN1Sequence.size());
        }
        Enumeration objects = aSN1Sequence.getObjects();
        this.f461p = DERInteger.getInstance(objects.nextElement());
        this.f462q = DERInteger.getInstance(objects.nextElement());
        this.f460g = DERInteger.getInstance(objects.nextElement());
    }

    public static DSAParameter getInstance(Object obj) {
        return obj instanceof DSAParameter ? (DSAParameter) obj : obj != null ? new DSAParameter(ASN1Sequence.getInstance(obj)) : null;
    }

    public static DSAParameter getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public BigInteger getG() {
        return this.f460g.getPositiveValue();
    }

    public BigInteger getP() {
        return this.f461p.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.f462q.getPositiveValue();
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(this.f461p);
        aSN1EncodableVector.add(this.f462q);
        aSN1EncodableVector.add(this.f460g);
        return new DERSequence(aSN1EncodableVector);
    }
}
