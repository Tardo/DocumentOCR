package org.spongycastle.asn1.sec;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.util.BigIntegers;

public class ECPrivateKeyStructure extends ASN1Encodable {
    private ASN1Sequence seq;

    public ECPrivateKeyStructure(ASN1Sequence seq) {
        this.seq = seq;
    }

    public ECPrivateKeyStructure(BigInteger key) {
        byte[] bytes = BigIntegers.asUnsignedByteArray(key);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(1));
        v.add(new DEROctetString(bytes));
        this.seq = new DERSequence(v);
    }

    public ECPrivateKeyStructure(BigInteger key, ASN1Encodable parameters) {
        this(key, null, parameters);
    }

    public ECPrivateKeyStructure(BigInteger key, DERBitString publicKey, ASN1Encodable parameters) {
        byte[] bytes = BigIntegers.asUnsignedByteArray(key);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(1));
        v.add(new DEROctetString(bytes));
        if (parameters != null) {
            v.add(new DERTaggedObject(true, 0, parameters));
        }
        if (publicKey != null) {
            v.add(new DERTaggedObject(true, 1, publicKey));
        }
        this.seq = new DERSequence(v);
    }

    public BigInteger getKey() {
        return new BigInteger(1, ((ASN1OctetString) this.seq.getObjectAt(1)).getOctets());
    }

    public DERBitString getPublicKey() {
        return (DERBitString) getObjectInTag(1);
    }

    public ASN1Object getParameters() {
        return getObjectInTag(0);
    }

    private ASN1Object getObjectInTag(int tagNo) {
        Enumeration e = this.seq.getObjects();
        while (e.hasMoreElements()) {
            DEREncodable obj = (DEREncodable) e.nextElement();
            if (obj instanceof ASN1TaggedObject) {
                ASN1TaggedObject tag = (ASN1TaggedObject) obj;
                if (tag.getTagNo() == tagNo) {
                    return (ASN1Object) tag.getObject().getDERObject();
                }
            }
        }
        return null;
    }

    public DERObject toASN1Object() {
        return this.seq;
    }
}
