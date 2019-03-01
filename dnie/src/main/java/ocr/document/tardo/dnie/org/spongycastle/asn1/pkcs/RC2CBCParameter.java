package org.spongycastle.asn1.pkcs;

import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

public class RC2CBCParameter extends ASN1Encodable {
    ASN1OctetString iv;
    DERInteger version;

    public static RC2CBCParameter getInstance(Object o) {
        if (o instanceof ASN1Sequence) {
            return new RC2CBCParameter((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in RC2CBCParameter factory");
    }

    public RC2CBCParameter(byte[] iv) {
        this.version = null;
        this.iv = new DEROctetString(iv);
    }

    public RC2CBCParameter(int parameterVersion, byte[] iv) {
        this.version = new DERInteger(parameterVersion);
        this.iv = new DEROctetString(iv);
    }

    public RC2CBCParameter(ASN1Sequence seq) {
        if (seq.size() == 1) {
            this.version = null;
            this.iv = (ASN1OctetString) seq.getObjectAt(0);
            return;
        }
        this.version = (DERInteger) seq.getObjectAt(0);
        this.iv = (ASN1OctetString) seq.getObjectAt(1);
    }

    public BigInteger getRC2ParameterVersion() {
        if (this.version == null) {
            return null;
        }
        return this.version.getValue();
    }

    public byte[] getIV() {
        return this.iv.getOctets();
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.version != null) {
            v.add(this.version);
        }
        v.add(this.iv);
        return new DERSequence(v);
    }
}
