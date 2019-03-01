package org.spongycastle.asn1.x509;

import java.io.IOException;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class SubjectPublicKeyInfo extends ASN1Encodable {
    private AlgorithmIdentifier algId;
    private DERBitString keyData;

    public static SubjectPublicKeyInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SubjectPublicKeyInfo getInstance(Object obj) {
        if (obj instanceof SubjectPublicKeyInfo) {
            return (SubjectPublicKeyInfo) obj;
        }
        if (obj != null) {
            return new SubjectPublicKeyInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public SubjectPublicKeyInfo(AlgorithmIdentifier algId, DEREncodable publicKey) {
        this.keyData = new DERBitString(publicKey);
        this.algId = algId;
    }

    public SubjectPublicKeyInfo(AlgorithmIdentifier algId, byte[] publicKey) {
        this.keyData = new DERBitString(publicKey);
        this.algId = algId;
    }

    public SubjectPublicKeyInfo(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        this.algId = AlgorithmIdentifier.getInstance(e.nextElement());
        this.keyData = DERBitString.getInstance(e.nextElement());
    }

    public AlgorithmIdentifier getAlgorithmId() {
        return this.algId;
    }

    public DERObject getPublicKey() throws IOException {
        return new ASN1InputStream(this.keyData.getBytes()).readObject();
    }

    public DERBitString getPublicKeyData() {
        return this.keyData;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.algId);
        v.add(this.keyData);
        return new DERSequence(v);
    }
}
