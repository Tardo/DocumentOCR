package org.spongycastle.asn1.pkcs;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class DHParameter extends ASN1Encodable {
    /* renamed from: g */
    DERInteger f545g;
    /* renamed from: l */
    DERInteger f546l;
    /* renamed from: p */
    DERInteger f547p;

    public DHParameter(BigInteger p, BigInteger g, int l) {
        this.f547p = new DERInteger(p);
        this.f545g = new DERInteger(g);
        if (l != 0) {
            this.f546l = new DERInteger(l);
        } else {
            this.f546l = null;
        }
    }

    public DHParameter(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.f547p = (DERInteger) e.nextElement();
        this.f545g = (DERInteger) e.nextElement();
        if (e.hasMoreElements()) {
            this.f546l = (DERInteger) e.nextElement();
        } else {
            this.f546l = null;
        }
    }

    public BigInteger getP() {
        return this.f547p.getPositiveValue();
    }

    public BigInteger getG() {
        return this.f545g.getPositiveValue();
    }

    public BigInteger getL() {
        if (this.f546l == null) {
            return null;
        }
        return this.f546l.getPositiveValue();
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.f547p);
        v.add(this.f545g);
        if (getL() != null) {
            v.add(this.f546l);
        }
        return new DERSequence(v);
    }
}
