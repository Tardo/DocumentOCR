package org.spongycastle.asn1.pkcs;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.BERTaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class EncryptedData extends ASN1Encodable {
    DERObjectIdentifier bagId;
    DERObject bagValue;
    ASN1Sequence data;

    public static EncryptedData getInstance(Object obj) {
        if (obj instanceof EncryptedData) {
            return (EncryptedData) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new EncryptedData((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public EncryptedData(ASN1Sequence seq) {
        if (((DERInteger) seq.getObjectAt(0)).getValue().intValue() != 0) {
            throw new IllegalArgumentException("sequence not version 0");
        }
        this.data = (ASN1Sequence) seq.getObjectAt(1);
    }

    public EncryptedData(DERObjectIdentifier contentType, AlgorithmIdentifier encryptionAlgorithm, DEREncodable content) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(contentType);
        v.add(encryptionAlgorithm.getDERObject());
        v.add(new BERTaggedObject(false, 0, content));
        this.data = new BERSequence(v);
    }

    public DERObjectIdentifier getContentType() {
        return (DERObjectIdentifier) this.data.getObjectAt(0);
    }

    public AlgorithmIdentifier getEncryptionAlgorithm() {
        return AlgorithmIdentifier.getInstance(this.data.getObjectAt(1));
    }

    public ASN1OctetString getContent() {
        if (this.data.size() == 3) {
            return ASN1OctetString.getInstance((DERTaggedObject) this.data.getObjectAt(2), false);
        }
        return null;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(0));
        v.add(this.data);
        return new BERSequence(v);
    }
}
