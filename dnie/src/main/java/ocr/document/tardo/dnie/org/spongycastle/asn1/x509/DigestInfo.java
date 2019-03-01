package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

public class DigestInfo extends ASN1Encodable {
    private AlgorithmIdentifier algId;
    private byte[] digest;

    public static DigestInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static DigestInfo getInstance(Object obj) {
        if (obj instanceof DigestInfo) {
            return (DigestInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new DigestInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public DigestInfo(AlgorithmIdentifier algId, byte[] digest) {
        this.digest = digest;
        this.algId = algId;
    }

    public DigestInfo(ASN1Sequence obj) {
        Enumeration e = obj.getObjects();
        this.algId = AlgorithmIdentifier.getInstance(e.nextElement());
        this.digest = ASN1OctetString.getInstance(e.nextElement()).getOctets();
    }

    public AlgorithmIdentifier getAlgorithmId() {
        return this.algId;
    }

    public byte[] getDigest() {
        return this.digest;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.algId);
        v.add(new DEROctetString(this.digest));
        return new DERSequence(v);
    }
}
