package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class KeyAgreeRecipientInfo extends ASN1Encodable {
    private AlgorithmIdentifier keyEncryptionAlgorithm;
    private OriginatorIdentifierOrKey originator;
    private ASN1Sequence recipientEncryptedKeys;
    private ASN1OctetString ukm;
    private DERInteger version;

    public KeyAgreeRecipientInfo(OriginatorIdentifierOrKey originator, ASN1OctetString ukm, AlgorithmIdentifier keyEncryptionAlgorithm, ASN1Sequence recipientEncryptedKeys) {
        this.version = new DERInteger(3);
        this.originator = originator;
        this.ukm = ukm;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.recipientEncryptedKeys = recipientEncryptedKeys;
    }

    public KeyAgreeRecipientInfo(ASN1Sequence seq) {
        int index = 0 + 1;
        this.version = (DERInteger) seq.getObjectAt(0);
        int index2 = index + 1;
        this.originator = OriginatorIdentifierOrKey.getInstance((ASN1TaggedObject) seq.getObjectAt(index), true);
        if (seq.getObjectAt(index2) instanceof ASN1TaggedObject) {
            index = index2 + 1;
            this.ukm = ASN1OctetString.getInstance((ASN1TaggedObject) seq.getObjectAt(index2), true);
            index2 = index;
        }
        index = index2 + 1;
        this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(index2));
        index2 = index + 1;
        this.recipientEncryptedKeys = (ASN1Sequence) seq.getObjectAt(index);
    }

    public static KeyAgreeRecipientInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static KeyAgreeRecipientInfo getInstance(Object obj) {
        if (obj == null || (obj instanceof KeyAgreeRecipientInfo)) {
            return (KeyAgreeRecipientInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new KeyAgreeRecipientInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Illegal object in KeyAgreeRecipientInfo: " + obj.getClass().getName());
    }

    public DERInteger getVersion() {
        return this.version;
    }

    public OriginatorIdentifierOrKey getOriginator() {
        return this.originator;
    }

    public ASN1OctetString getUserKeyingMaterial() {
        return this.ukm;
    }

    public AlgorithmIdentifier getKeyEncryptionAlgorithm() {
        return this.keyEncryptionAlgorithm;
    }

    public ASN1Sequence getRecipientEncryptedKeys() {
        return this.recipientEncryptedKeys;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        v.add(new DERTaggedObject(true, 0, this.originator));
        if (this.ukm != null) {
            v.add(new DERTaggedObject(true, 1, this.ukm));
        }
        v.add(this.keyEncryptionAlgorithm);
        v.add(this.recipientEncryptedKeys);
        return new DERSequence(v);
    }
}
