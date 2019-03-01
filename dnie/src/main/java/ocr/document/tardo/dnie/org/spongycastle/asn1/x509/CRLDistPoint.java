package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class CRLDistPoint extends ASN1Encodable {
    ASN1Sequence seq = null;

    public static CRLDistPoint getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CRLDistPoint getInstance(Object obj) {
        if ((obj instanceof CRLDistPoint) || obj == null) {
            return (CRLDistPoint) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new CRLDistPoint((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public CRLDistPoint(ASN1Sequence seq) {
        this.seq = seq;
    }

    public CRLDistPoint(DistributionPoint[] points) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i != points.length; i++) {
            v.add(points[i]);
        }
        this.seq = new DERSequence(v);
    }

    public DistributionPoint[] getDistributionPoints() {
        DistributionPoint[] dp = new DistributionPoint[this.seq.size()];
        for (int i = 0; i != this.seq.size(); i++) {
            dp[i] = DistributionPoint.getInstance(this.seq.getObjectAt(i));
        }
        return dp;
    }

    public DERObject toASN1Object() {
        return this.seq;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String sep = System.getProperty("line.separator");
        buf.append("CRLDistPoint:");
        buf.append(sep);
        DistributionPoint[] dp = getDistributionPoints();
        for (int i = 0; i != dp.length; i++) {
            buf.append("    ");
            buf.append(dp[i]);
            buf.append(sep);
        }
        return buf.toString();
    }
}
