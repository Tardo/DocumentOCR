package org.spongycastle.asn1.x509;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class DSAParameter extends ASN1Encodable {
    /* renamed from: g */
    DERInteger f548g;
    /* renamed from: p */
    DERInteger f549p;
    /* renamed from: q */
    DERInteger f550q;

    public static DSAParameter getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static DSAParameter getInstance(Object obj) {
        if (obj == null || (obj instanceof DSAParameter)) {
            return (DSAParameter) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new DSAParameter((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid DSAParameter: " + obj.getClass().getName());
    }

    public DSAParameter(BigInteger p, BigInteger q, BigInteger g) {
        this.f549p = new DERInteger(p);
        this.f550q = new DERInteger(q);
        this.f548g = new DERInteger(g);
    }

    public DSAParameter(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        this.f549p = DERInteger.getInstance(e.nextElement());
        this.f550q = DERInteger.getInstance(e.nextElement());
        this.f548g = DERInteger.getInstance(e.nextElement());
    }

    public BigInteger getP() {
        return this.f549p.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.f550q.getPositiveValue();
    }

    public BigInteger getG() {
        return this.f548g.getPositiveValue();
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.f549p);
        v.add(this.f550q);
        v.add(this.f548g);
        return new DERSequence(v);
    }
}
