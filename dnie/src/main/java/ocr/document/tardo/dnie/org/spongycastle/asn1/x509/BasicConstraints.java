package org.spongycastle.asn1.x509;

import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBoolean;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class BasicConstraints extends ASN1Encodable {
    DERBoolean cA;
    DERInteger pathLenConstraint;

    public static BasicConstraints getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static BasicConstraints getInstance(Object obj) {
        if (obj == null || (obj instanceof BasicConstraints)) {
            return (BasicConstraints) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new BasicConstraints((ASN1Sequence) obj);
        }
        if (obj instanceof X509Extension) {
            return getInstance(X509Extension.convertValueToObject((X509Extension) obj));
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public BasicConstraints(ASN1Sequence seq) {
        this.cA = new DERBoolean(false);
        this.pathLenConstraint = null;
        if (seq.size() == 0) {
            this.cA = null;
            this.pathLenConstraint = null;
            return;
        }
        if (seq.getObjectAt(0) instanceof DERBoolean) {
            this.cA = DERBoolean.getInstance(seq.getObjectAt(0));
        } else {
            this.cA = null;
            this.pathLenConstraint = DERInteger.getInstance(seq.getObjectAt(0));
        }
        if (seq.size() <= 1) {
            return;
        }
        if (this.cA != null) {
            this.pathLenConstraint = DERInteger.getInstance(seq.getObjectAt(1));
            return;
        }
        throw new IllegalArgumentException("wrong sequence in constructor");
    }

    public BasicConstraints(boolean cA, int pathLenConstraint) {
        this.cA = new DERBoolean(false);
        this.pathLenConstraint = null;
        if (cA) {
            this.cA = new DERBoolean(cA);
            this.pathLenConstraint = new DERInteger(pathLenConstraint);
            return;
        }
        this.cA = null;
        this.pathLenConstraint = null;
    }

    public BasicConstraints(boolean cA) {
        this.cA = new DERBoolean(false);
        this.pathLenConstraint = null;
        if (cA) {
            this.cA = new DERBoolean(true);
        } else {
            this.cA = null;
        }
        this.pathLenConstraint = null;
    }

    public BasicConstraints(int pathLenConstraint) {
        this.cA = new DERBoolean(false);
        this.pathLenConstraint = null;
        this.cA = new DERBoolean(true);
        this.pathLenConstraint = new DERInteger(pathLenConstraint);
    }

    public boolean isCA() {
        return this.cA != null && this.cA.isTrue();
    }

    public BigInteger getPathLenConstraint() {
        if (this.pathLenConstraint != null) {
            return this.pathLenConstraint.getValue();
        }
        return null;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.cA != null) {
            v.add(this.cA);
        }
        if (this.pathLenConstraint != null) {
            v.add(this.pathLenConstraint);
        }
        return new DERSequence(v);
    }

    public String toString() {
        if (this.pathLenConstraint != null) {
            return "BasicConstraints: isCa(" + isCA() + "), pathLenConstraint = " + this.pathLenConstraint.getValue();
        }
        if (this.cA == null) {
            return "BasicConstraints: isCa(false)";
        }
        return "BasicConstraints: isCa(" + isCA() + ")";
    }
}
