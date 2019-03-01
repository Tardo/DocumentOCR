package org.spongycastle.asn1.x9;

import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECCurve.F2m;
import org.spongycastle.math.ec.ECCurve.Fp;
import org.spongycastle.math.ec.ECPoint;

public class X9ECParameters extends ASN1Encodable implements X9ObjectIdentifiers {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private ECCurve curve;
    private X9FieldID fieldID;
    /* renamed from: g */
    private ECPoint f561g;
    /* renamed from: h */
    private BigInteger f562h;
    /* renamed from: n */
    private BigInteger f563n;
    private byte[] seed;

    public X9ECParameters(ASN1Sequence seq) {
        if ((seq.getObjectAt(0) instanceof DERInteger) && ((DERInteger) seq.getObjectAt(0)).getValue().equals(ONE)) {
            X9Curve x9c = new X9Curve(new X9FieldID((ASN1Sequence) seq.getObjectAt(1)), (ASN1Sequence) seq.getObjectAt(2));
            this.curve = x9c.getCurve();
            this.f561g = new X9ECPoint(this.curve, (ASN1OctetString) seq.getObjectAt(3)).getPoint();
            this.f563n = ((DERInteger) seq.getObjectAt(4)).getValue();
            this.seed = x9c.getSeed();
            if (seq.size() == 6) {
                this.f562h = ((DERInteger) seq.getObjectAt(5)).getValue();
                return;
            }
            return;
        }
        throw new IllegalArgumentException("bad version in X9ECParameters");
    }

    public X9ECParameters(ECCurve curve, ECPoint g, BigInteger n) {
        this(curve, g, n, ONE, null);
    }

    public X9ECParameters(ECCurve curve, ECPoint g, BigInteger n, BigInteger h) {
        this(curve, g, n, h, null);
    }

    public X9ECParameters(ECCurve curve, ECPoint g, BigInteger n, BigInteger h, byte[] seed) {
        this.curve = curve;
        this.f561g = g;
        this.f563n = n;
        this.f562h = h;
        this.seed = seed;
        if (curve instanceof Fp) {
            this.fieldID = new X9FieldID(((Fp) curve).getQ());
        } else if (curve instanceof F2m) {
            F2m curveF2m = (F2m) curve;
            this.fieldID = new X9FieldID(curveF2m.getM(), curveF2m.getK1(), curveF2m.getK2(), curveF2m.getK3());
        }
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public ECPoint getG() {
        return this.f561g;
    }

    public BigInteger getN() {
        return this.f563n;
    }

    public BigInteger getH() {
        if (this.f562h == null) {
            return ONE;
        }
        return this.f562h;
    }

    public byte[] getSeed() {
        return this.seed;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(1));
        v.add(this.fieldID);
        v.add(new X9Curve(this.curve, this.seed));
        v.add(new X9ECPoint(this.f561g));
        v.add(new DERInteger(this.f563n));
        if (this.f562h != null) {
            v.add(new DERInteger(this.f562h));
        }
        return new DERSequence(v);
    }
}
