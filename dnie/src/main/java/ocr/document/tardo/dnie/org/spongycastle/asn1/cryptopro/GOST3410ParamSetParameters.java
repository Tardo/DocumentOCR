package org.spongycastle.asn1.cryptopro;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class GOST3410ParamSetParameters extends ASN1Encodable {
    /* renamed from: a */
    DERInteger f540a;
    int keySize;
    /* renamed from: p */
    DERInteger f541p;
    /* renamed from: q */
    DERInteger f542q;

    public static GOST3410ParamSetParameters getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GOST3410ParamSetParameters getInstance(Object obj) {
        if (obj == null || (obj instanceof GOST3410ParamSetParameters)) {
            return (GOST3410ParamSetParameters) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new GOST3410ParamSetParameters((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid GOST3410Parameter: " + obj.getClass().getName());
    }

    public GOST3410ParamSetParameters(int keySize, BigInteger p, BigInteger q, BigInteger a) {
        this.keySize = keySize;
        this.f541p = new DERInteger(p);
        this.f542q = new DERInteger(q);
        this.f540a = new DERInteger(a);
    }

    public GOST3410ParamSetParameters(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.keySize = ((DERInteger) e.nextElement()).getValue().intValue();
        this.f541p = (DERInteger) e.nextElement();
        this.f542q = (DERInteger) e.nextElement();
        this.f540a = (DERInteger) e.nextElement();
    }

    public int getLKeySize() {
        return this.keySize;
    }

    public int getKeySize() {
        return this.keySize;
    }

    public BigInteger getP() {
        return this.f541p.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.f542q.getPositiveValue();
    }

    public BigInteger getA() {
        return this.f540a.getPositiveValue();
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(this.keySize));
        v.add(this.f541p);
        v.add(this.f542q);
        v.add(this.f540a);
        return new DERSequence(v);
    }
}
