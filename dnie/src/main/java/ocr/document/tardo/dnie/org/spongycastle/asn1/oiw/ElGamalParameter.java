package org.spongycastle.asn1.oiw;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class ElGamalParameter extends ASN1Encodable {
    /* renamed from: g */
    DERInteger f543g;
    /* renamed from: p */
    DERInteger f544p;

    public ElGamalParameter(BigInteger p, BigInteger g) {
        this.f544p = new DERInteger(p);
        this.f543g = new DERInteger(g);
    }

    public ElGamalParameter(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.f544p = (DERInteger) e.nextElement();
        this.f543g = (DERInteger) e.nextElement();
    }

    public BigInteger getP() {
        return this.f544p.getPositiveValue();
    }

    public BigInteger getG() {
        return this.f543g.getPositiveValue();
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.f544p);
        v.add(this.f543g);
        return new DERSequence(v);
    }
}
