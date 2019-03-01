package org.bouncycastle.asn1.x9;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.F2m;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;

public class X9ECParameters extends ASN1Object implements X9ObjectIdentifiers {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private ECCurve curve;
    private X9FieldID fieldID;
    /* renamed from: g */
    private ECPoint f473g;
    /* renamed from: h */
    private BigInteger f474h;
    /* renamed from: n */
    private BigInteger f475n;
    private byte[] seed;

    private X9ECParameters(ASN1Sequence aSN1Sequence) {
        if ((aSN1Sequence.getObjectAt(0) instanceof ASN1Integer) && ((ASN1Integer) aSN1Sequence.getObjectAt(0)).getValue().equals(ONE)) {
            X9Curve x9Curve = new X9Curve(new X9FieldID((ASN1Sequence) aSN1Sequence.getObjectAt(1)), (ASN1Sequence) aSN1Sequence.getObjectAt(2));
            this.curve = x9Curve.getCurve();
            this.f473g = new X9ECPoint(this.curve, (ASN1OctetString) aSN1Sequence.getObjectAt(3)).getPoint();
            this.f475n = ((ASN1Integer) aSN1Sequence.getObjectAt(4)).getValue();
            this.seed = x9Curve.getSeed();
            if (aSN1Sequence.size() == 6) {
                this.f474h = ((ASN1Integer) aSN1Sequence.getObjectAt(5)).getValue();
                return;
            }
            return;
        }
        throw new IllegalArgumentException("bad version in X9ECParameters");
    }

    public X9ECParameters(ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger) {
        this(eCCurve, eCPoint, bigInteger, ONE, null);
    }

    public X9ECParameters(ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger, BigInteger bigInteger2) {
        this(eCCurve, eCPoint, bigInteger, bigInteger2, null);
    }

    public X9ECParameters(ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger, BigInteger bigInteger2, byte[] bArr) {
        this.curve = eCCurve;
        this.f473g = eCPoint;
        this.f475n = bigInteger;
        this.f474h = bigInteger2;
        this.seed = bArr;
        if (eCCurve instanceof Fp) {
            this.fieldID = new X9FieldID(((Fp) eCCurve).getQ());
        } else if (eCCurve instanceof F2m) {
            F2m f2m = (F2m) eCCurve;
            this.fieldID = new X9FieldID(f2m.getM(), f2m.getK1(), f2m.getK2(), f2m.getK3());
        }
    }

    public static X9ECParameters getInstance(Object obj) {
        return obj instanceof X9ECParameters ? (X9ECParameters) obj : obj != null ? new X9ECParameters(ASN1Sequence.getInstance(obj)) : null;
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public ECPoint getG() {
        return this.f473g;
    }

    public BigInteger getH() {
        return this.f474h == null ? ONE : this.f474h;
    }

    public BigInteger getN() {
        return this.f475n;
    }

    public byte[] getSeed() {
        return this.seed;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(new ASN1Integer(1));
        aSN1EncodableVector.add(this.fieldID);
        aSN1EncodableVector.add(new X9Curve(this.curve, this.seed));
        aSN1EncodableVector.add(new X9ECPoint(this.f473g));
        aSN1EncodableVector.add(new ASN1Integer(this.f475n));
        if (this.f474h != null) {
            aSN1EncodableVector.add(new ASN1Integer(this.f474h));
        }
        return new DERSequence(aSN1EncodableVector);
    }
}
