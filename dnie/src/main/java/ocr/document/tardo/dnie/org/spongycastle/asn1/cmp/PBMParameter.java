package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class PBMParameter extends ASN1Encodable {
    private DERInteger iterationCount;
    private AlgorithmIdentifier mac;
    private AlgorithmIdentifier owf;
    private ASN1OctetString salt;

    private PBMParameter(ASN1Sequence seq) {
        this.salt = ASN1OctetString.getInstance(seq.getObjectAt(0));
        this.owf = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.iterationCount = DERInteger.getInstance(seq.getObjectAt(2));
        this.mac = AlgorithmIdentifier.getInstance(seq.getObjectAt(3));
    }

    public static PBMParameter getInstance(Object o) {
        if (o instanceof PBMParameter) {
            return (PBMParameter) o;
        }
        if (o instanceof ASN1Sequence) {
            return new PBMParameter((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public PBMParameter(byte[] salt, AlgorithmIdentifier owf, int iterationCount, AlgorithmIdentifier mac) {
        this(new DEROctetString(salt), owf, new DERInteger(iterationCount), mac);
    }

    public PBMParameter(ASN1OctetString salt, AlgorithmIdentifier owf, DERInteger iterationCount, AlgorithmIdentifier mac) {
        this.salt = salt;
        this.owf = owf;
        this.iterationCount = iterationCount;
        this.mac = mac;
    }

    public ASN1OctetString getSalt() {
        return this.salt;
    }

    public AlgorithmIdentifier getOwf() {
        return this.owf;
    }

    public DERInteger getIterationCount() {
        return this.iterationCount;
    }

    public AlgorithmIdentifier getMac() {
        return this.mac;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.salt);
        v.add(this.owf);
        v.add(this.iterationCount);
        v.add(this.mac);
        return new DERSequence(v);
    }
}
