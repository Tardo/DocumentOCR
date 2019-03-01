package de.tsenger.androsmex.asn1;

import java.math.BigInteger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class AmDHPublicKey extends AmPublicKey implements DHPublicKey {
    private static final long serialVersionUID = 5691151250780854614L;
    private final String algorithm = "DH";
    private final String format = "CVC";
    /* renamed from: g */
    private DERTaggedObject f599g = null;
    /* renamed from: p */
    private DERTaggedObject f600p = null;
    /* renamed from: q */
    private DERTaggedObject f601q = null;
    /* renamed from: y */
    private DERTaggedObject f602y = null;

    public AmDHPublicKey(DERSequence seq) {
        super(seq);
        decode(seq);
    }

    public AmDHPublicKey(String oidString, BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        super(oidString);
        this.f600p = new DERTaggedObject(false, 1, new DERInteger(p));
        this.f601q = new DERTaggedObject(false, 2, new DERInteger(q));
        this.f599g = new DERTaggedObject(false, 3, new DERInteger(g));
        this.f602y = new DERTaggedObject(false, 4, new DERInteger(y));
        this.vec.add(this.f600p);
        this.vec.add(this.f601q);
        this.vec.add(this.f599g);
        this.vec.add(this.f602y);
    }

    public AmDHPublicKey(String oidString, BigInteger y) {
        super(oidString);
        this.f602y = new DERTaggedObject(false, 4, new DERInteger(y));
        this.vec.add(this.f602y);
    }

    public String getAlgorithm() {
        return "DH";
    }

    public String getFormat() {
        return "CVC";
    }

    public byte[] getEncoded() {
        return super.getDEREncoded();
    }

    protected void decode(DERSequence seq) {
        for (int i = 1; i < seq.size(); i++) {
            DERTaggedObject to = (DERTaggedObject) seq.getObjectAt(i);
            switch (to.getTagNo()) {
                case 1:
                    this.f600p = to;
                    break;
                case 2:
                    this.f601q = to;
                    break;
                case 3:
                    this.f599g = to;
                    break;
                case 4:
                    this.f602y = to;
                    break;
                default:
                    break;
            }
        }
    }

    public BigInteger getP() {
        if (this.f600p == null) {
            return null;
        }
        return ((DERInteger) this.f600p.getObjectParser(2, false)).getPositiveValue();
    }

    public BigInteger getG() {
        if (this.f599g == null) {
            return null;
        }
        return ((DERInteger) this.f599g.getObjectParser(2, false)).getPositiveValue();
    }

    public BigInteger getQ() {
        if (this.f601q == null) {
            return null;
        }
        return ((DERInteger) this.f601q.getObjectParser(2, false)).getPositiveValue();
    }

    public BigInteger getY() {
        if (this.f602y == null) {
            return null;
        }
        return ((DERInteger) this.f602y.getObjectParser(2, false)).getPositiveValue();
    }

    public DHParameterSpec getParams() {
        return new DHParameterSpec(getP(), getG());
    }
}
