package de.tsenger.androsmex.asn1;

import de.tsenger.androsmex.tools.Converter;
import java.math.BigInteger;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.math.ec.ECCurve.Fp;
import org.spongycastle.math.ec.ECPoint;

public class AmECPublicKey extends AmPublicKey implements ECPublicKey {
    private static final long serialVersionUID = 3574151885727849955L;
    /* renamed from: G */
    private DERTaggedObject f603G = null;
    /* renamed from: Y */
    private DERTaggedObject f604Y = null;
    /* renamed from: a */
    private DERTaggedObject f605a = null;
    private final String algorithm = "EC";
    /* renamed from: b */
    private DERTaggedObject f606b = null;
    /* renamed from: f */
    private DERTaggedObject f607f = null;
    private final String format = "CVC";
    /* renamed from: p */
    private DERTaggedObject f608p = null;
    /* renamed from: r */
    private DERTaggedObject f609r = null;

    public AmECPublicKey(DERSequence seq) {
        super(seq);
        decode(seq);
    }

    public AmECPublicKey(String oidString, BigInteger p, BigInteger a, BigInteger b, ECPoint G, BigInteger r, ECPoint Y, BigInteger f) {
        super(oidString);
        this.f608p = new DERTaggedObject(false, 1, new DERInteger(p));
        this.f605a = new DERTaggedObject(false, 2, new DERInteger(a));
        this.f606b = new DERTaggedObject(false, 3, new DERInteger(b));
        this.f603G = new DERTaggedObject(false, 4, new DEROctetString(G.getEncoded()));
        this.f609r = new DERTaggedObject(false, 5, new DERInteger(r));
        this.f604Y = new DERTaggedObject(false, 6, new DEROctetString(Y.getEncoded()));
        this.f607f = new DERTaggedObject(false, 7, new DERInteger(f));
        this.vec.add(this.f608p);
        this.vec.add(this.f605a);
        this.vec.add(this.f606b);
        this.vec.add(this.f603G);
        this.vec.add(this.f609r);
        this.vec.add(this.f604Y);
        this.vec.add(this.f607f);
    }

    public AmECPublicKey(String oidString, ECPoint Y) {
        super(oidString);
        this.f604Y = new DERTaggedObject(false, 6, new DEROctetString(Y.getEncoded()));
        this.vec.add(this.f604Y);
    }

    public String getAlgorithm() {
        return "EC";
    }

    public String getFormat() {
        return "CVC";
    }

    public BigInteger getP() {
        if (this.f608p == null) {
            return null;
        }
        return DERInteger.getInstance(this.f608p, false).getPositiveValue();
    }

    public BigInteger getA() {
        if (this.f605a == null) {
            return null;
        }
        return DERInteger.getInstance(this.f605a, false).getPositiveValue();
    }

    public BigInteger getB() {
        if (this.f606b == null) {
            return null;
        }
        return DERInteger.getInstance(this.f606b, false).getPositiveValue();
    }

    public byte[] getG() {
        if (this.f603G == null) {
            return null;
        }
        return ((DEROctetString) ASN1OctetString.getInstance(this.f603G, false)).getOctets();
    }

    public BigInteger getR() {
        if (this.f609r == null) {
            return null;
        }
        return DERInteger.getInstance(this.f609r, false).getPositiveValue();
    }

    public byte[] getY() {
        if (this.f604Y == null) {
            return null;
        }
        return ((DEROctetString) ASN1OctetString.getInstance(this.f604Y, false)).getOctets();
    }

    public BigInteger getF() {
        if (this.f607f == null) {
            return null;
        }
        return DERInteger.getInstance(this.f607f, false).getPositiveValue();
    }

    public byte[] getEncoded() {
        return super.getDEREncoded();
    }

    protected void decode(DERSequence seq) {
        for (int i = 1; i < seq.size(); i++) {
            DERTaggedObject to = (DERTaggedObject) seq.getObjectAt(i);
            switch (to.getTagNo()) {
                case 1:
                    this.f608p = to;
                    this.vec.add(this.f608p);
                    break;
                case 2:
                    this.f605a = to;
                    this.vec.add(this.f605a);
                    break;
                case 3:
                    this.f606b = to;
                    this.vec.add(this.f606b);
                    break;
                case 4:
                    this.f603G = to;
                    this.vec.add(this.f603G);
                    break;
                case 5:
                    this.f609r = to;
                    this.vec.add(this.f609r);
                    break;
                case 6:
                    this.f604Y = to;
                    this.vec.add(this.f604Y);
                    break;
                case 7:
                    this.f607f = to;
                    this.vec.add(this.f607f);
                    break;
                default:
                    break;
            }
        }
    }

    public ECParameterSpec getParameters() {
        Fp curve = new Fp(getP(), getA(), getB());
        return new ECParameterSpec(curve, Converter.byteArrayToECPoint(getG(), curve), getR(), getF());
    }

    public ECPoint getQ() {
        return Converter.byteArrayToECPoint(getY(), new Fp(getP(), getA(), getB()));
    }
}
