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

public class ECGOST3410ParamSetParameters extends ASN1Encodable {
    /* renamed from: a */
    DERInteger f534a;
    /* renamed from: b */
    DERInteger f535b;
    /* renamed from: p */
    DERInteger f536p;
    /* renamed from: q */
    DERInteger f537q;
    /* renamed from: x */
    DERInteger f538x;
    /* renamed from: y */
    DERInteger f539y;

    public static ECGOST3410ParamSetParameters getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
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

    public ECGOST3410ParamSetParameters(BigInteger a, BigInteger b, BigInteger p, BigInteger q, int x, BigInteger y) {
        this.f534a = new DERInteger(a);
        this.f535b = new DERInteger(b);
        this.f536p = new DERInteger(p);
        this.f537q = new DERInteger(q);
        this.f538x = new DERInteger(x);
        this.f539y = new DERInteger(y);
    }

    public ECGOST3410ParamSetParameters(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.f534a = (DERInteger) e.nextElement();
        this.f535b = (DERInteger) e.nextElement();
        this.f536p = (DERInteger) e.nextElement();
        this.f537q = (DERInteger) e.nextElement();
        this.f538x = (DERInteger) e.nextElement();
        this.f539y = (DERInteger) e.nextElement();
    }

    public BigInteger getP() {
        return this.f536p.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.f537q.getPositiveValue();
    }

    public BigInteger getA() {
        return this.f534a.getPositiveValue();
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.f534a);
        v.add(this.f535b);
        v.add(this.f536p);
        v.add(this.f537q);
        v.add(this.f538x);
        v.add(this.f539y);
        return new DERSequence(v);
    }
}
