package org.spongycastle.asn1.x9;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class DHDomainParameters extends ASN1Encodable {
    /* renamed from: g */
    private DERInteger f556g;
    /* renamed from: j */
    private DERInteger f557j;
    /* renamed from: p */
    private DERInteger f558p;
    /* renamed from: q */
    private DERInteger f559q;
    private DHValidationParms validationParms;

    public static DHDomainParameters getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
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

    public DHDomainParameters(DERInteger p, DERInteger g, DERInteger q, DERInteger j, DHValidationParms validationParms) {
        if (p == null) {
            throw new IllegalArgumentException("'p' cannot be null");
        } else if (g == null) {
            throw new IllegalArgumentException("'g' cannot be null");
        } else if (q == null) {
            throw new IllegalArgumentException("'q' cannot be null");
        } else {
            this.f558p = p;
            this.f556g = g;
            this.f559q = q;
            this.f557j = j;
            this.validationParms = validationParms;
        }
    }

    private DHDomainParameters(ASN1Sequence seq) {
        if (seq.size() < 3 || seq.size() > 5) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        this.f558p = DERInteger.getInstance(e.nextElement());
        this.f556g = DERInteger.getInstance(e.nextElement());
        this.f559q = DERInteger.getInstance(e.nextElement());
        DEREncodable next = getNext(e);
        if (next != null && (next instanceof DERInteger)) {
            this.f557j = DERInteger.getInstance(next);
            next = getNext(e);
        }
        if (next != null) {
            this.validationParms = DHValidationParms.getInstance(next.getDERObject());
        }
    }

    private static DEREncodable getNext(Enumeration e) {
        return e.hasMoreElements() ? (DEREncodable) e.nextElement() : null;
    }

    public DERInteger getP() {
        return this.f558p;
    }

    public DERInteger getG() {
        return this.f556g;
    }

    public DERInteger getQ() {
        return this.f559q;
    }

    public DERInteger getJ() {
        return this.f557j;
    }

    public DHValidationParms getValidationParms() {
        return this.validationParms;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.f558p);
        v.add(this.f556g);
        v.add(this.f559q);
        if (this.f557j != null) {
            v.add(this.f557j);
        }
        if (this.validationParms != null) {
            v.add(this.validationParms);
        }
        return new DERSequence(v);
    }
}
