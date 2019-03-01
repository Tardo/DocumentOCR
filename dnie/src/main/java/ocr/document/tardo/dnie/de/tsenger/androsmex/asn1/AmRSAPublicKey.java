package de.tsenger.androsmex.asn1;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class AmRSAPublicKey extends AmPublicKey implements RSAPublicKey {
    private static final long serialVersionUID = -7184069684377504157L;
    private final String algorithm = "RSA";
    /* renamed from: e */
    private DERTaggedObject f610e = null;
    private final String format = "CVC";
    /* renamed from: n */
    private DERTaggedObject f611n = null;

    public AmRSAPublicKey(DERSequence seq) {
        super(seq);
        decode(seq);
    }

    public AmRSAPublicKey(String oidString, BigInteger n, BigInteger e) {
        super(oidString);
        this.f611n = new DERTaggedObject(false, 1, new DERInteger(n));
        this.f610e = new DERTaggedObject(false, 2, new DERInteger(e));
        this.vec.add(this.f611n);
        this.vec.add(this.f610e);
    }

    public String getAlgorithm() {
        return "RSA";
    }

    public byte[] getEncoded() {
        this.vec.add(this.f611n);
        this.vec.add(this.f610e);
        return super.getDEREncoded();
    }

    public String getFormat() {
        return "CVC";
    }

    protected void decode(DERSequence seq) {
        for (int i = 1; i < seq.size(); i++) {
            DERTaggedObject to = (DERTaggedObject) seq.getObjectAt(i);
            switch (to.getTagNo()) {
                case 1:
                    this.f611n = to;
                    break;
                case 2:
                    this.f610e = to;
                    break;
                default:
                    break;
            }
        }
    }

    public BigInteger getModulus() {
        if (this.f611n == null) {
            return null;
        }
        return ((DERInteger) this.f611n.getObjectParser(2, false)).getPositiveValue();
    }

    public BigInteger getPublicExponent() {
        if (this.f610e == null) {
            return null;
        }
        return ((DERInteger) this.f610e.getObjectParser(2, false)).getPositiveValue();
    }
}
