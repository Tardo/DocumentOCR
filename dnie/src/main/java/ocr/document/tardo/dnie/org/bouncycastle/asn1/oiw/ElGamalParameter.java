package org.bouncycastle.asn1.oiw;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ElGamalParameter extends ASN1Object {
    /* renamed from: g */
    ASN1Integer f447g;
    /* renamed from: p */
    ASN1Integer f448p;

    public ElGamalParameter(BigInteger bigInteger, BigInteger bigInteger2) {
        this.f448p = new ASN1Integer(bigInteger);
        this.f447g = new ASN1Integer(bigInteger2);
    }

    public ElGamalParameter(ASN1Sequence aSN1Sequence) {
        Enumeration objects = aSN1Sequence.getObjects();
        this.f448p = (ASN1Integer) objects.nextElement();
        this.f447g = (ASN1Integer) objects.nextElement();
    }

    public BigInteger getG() {
        return this.f447g.getPositiveValue();
    }

    public BigInteger getP() {
        return this.f448p.getPositiveValue();
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(this.f448p);
        aSN1EncodableVector.add(this.f447g);
        return new DERSequence(aSN1EncodableVector);
    }
}
