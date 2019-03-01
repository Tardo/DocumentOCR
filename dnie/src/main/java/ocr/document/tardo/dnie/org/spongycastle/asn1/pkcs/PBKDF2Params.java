package org.spongycastle.asn1.pkcs;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

public class PBKDF2Params extends ASN1Encodable {
    DERInteger iterationCount;
    DERInteger keyLength;
    ASN1OctetString octStr;

    public static PBKDF2Params getInstance(Object obj) {
        if (obj instanceof PBKDF2Params) {
            return (PBKDF2Params) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new PBKDF2Params((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public PBKDF2Params(byte[] salt, int iterationCount) {
        this.octStr = new DEROctetString(salt);
        this.iterationCount = new DERInteger(iterationCount);
    }

    public PBKDF2Params(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.octStr = (ASN1OctetString) e.nextElement();
        this.iterationCount = (DERInteger) e.nextElement();
        if (e.hasMoreElements()) {
            this.keyLength = (DERInteger) e.nextElement();
        } else {
            this.keyLength = null;
        }
    }

    public byte[] getSalt() {
        return this.octStr.getOctets();
    }

    public BigInteger getIterationCount() {
        return this.iterationCount.getValue();
    }

    public BigInteger getKeyLength() {
        if (this.keyLength != null) {
            return this.keyLength.getValue();
        }
        return null;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.octStr);
        v.add(this.iterationCount);
        if (this.keyLength != null) {
            v.add(this.keyLength);
        }
        return new DERSequence(v);
    }
}
