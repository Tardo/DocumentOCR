package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class KEKRecipientInfo extends ASN1Encodable {
    private ASN1OctetString encryptedKey;
    private KEKIdentifier kekid;
    private AlgorithmIdentifier keyEncryptionAlgorithm;
    private DERInteger version;

    public KEKRecipientInfo(KEKIdentifier kekid, AlgorithmIdentifier keyEncryptionAlgorithm, ASN1OctetString encryptedKey) {
        this.version = new DERInteger(4);
        this.kekid = kekid;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.encryptedKey = encryptedKey;
    }

    public KEKRecipientInfo(ASN1Sequence seq) {
        this.version = (DERInteger) seq.getObjectAt(0);
        this.kekid = KEKIdentifier.getInstance(seq.getObjectAt(1));
        this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
        this.encryptedKey = (ASN1OctetString) seq.getObjectAt(3);
    }

    public static KEKRecipientInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static KEKRecipientInfo getInstance(Object obj) {
        if (obj == null || (obj instanceof KEKRecipientInfo)) {
            return (KEKRecipientInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new KEKRecipientInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid KEKRecipientInfo: " + obj.getClass().getName());
    }

    public DERInteger getVersion() {
        return this.version;
    }

    public KEKIdentifier getKekid() {
        return this.kekid;
    }

    public AlgorithmIdentifier getKeyEncryptionAlgorithm() {
        return this.keyEncryptionAlgorithm;
    }

    public ASN1OctetString getEncryptedKey() {
        return this.encryptedKey;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        v.add(this.kekid);
        v.add(this.keyEncryptionAlgorithm);
        v.add(this.encryptedKey);
        return new DERSequence(v);
    }
}
