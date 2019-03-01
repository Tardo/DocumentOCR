package org.spongycastle.asn1.pkcs;

import java.io.IOException;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class PrivateKeyInfo extends ASN1Encodable {
    private AlgorithmIdentifier algId;
    private ASN1Set attributes;
    private DERObject privKey;

    public static PrivateKeyInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PrivateKeyInfo getInstance(Object obj) {
        if (obj instanceof PrivateKeyInfo) {
            return (PrivateKeyInfo) obj;
        }
        if (obj != null) {
            return new PrivateKeyInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public PrivateKeyInfo(AlgorithmIdentifier algId, DERObject privateKey) {
        this(algId, privateKey, null);
    }

    public PrivateKeyInfo(AlgorithmIdentifier algId, DERObject privateKey, ASN1Set attributes) {
        this.privKey = privateKey;
        this.algId = algId;
        this.attributes = attributes;
    }

    public PrivateKeyInfo(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        if (((DERInteger) e.nextElement()).getValue().intValue() != 0) {
            throw new IllegalArgumentException("wrong version for private key info");
        }
        this.algId = new AlgorithmIdentifier((ASN1Sequence) e.nextElement());
        try {
            this.privKey = new ASN1InputStream(((ASN1OctetString) e.nextElement()).getOctets()).readObject();
            if (e.hasMoreElements()) {
                this.attributes = ASN1Set.getInstance((ASN1TaggedObject) e.nextElement(), false);
            }
        } catch (IOException e2) {
            throw new IllegalArgumentException("Error recoverying private key from sequence");
        }
    }

    public AlgorithmIdentifier getAlgorithmId() {
        return this.algId;
    }

    public DERObject getPrivateKey() {
        return this.privKey;
    }

    public ASN1Set getAttributes() {
        return this.attributes;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(0));
        v.add(this.algId);
        v.add(new DEROctetString(this.privKey));
        if (this.attributes != null) {
            v.add(new DERTaggedObject(false, 0, this.attributes));
        }
        return new DERSequence(v);
    }
}
