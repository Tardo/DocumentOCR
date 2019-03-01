package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.BERTaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class EncryptedContentInfo extends ASN1Encodable {
    private AlgorithmIdentifier contentEncryptionAlgorithm;
    private DERObjectIdentifier contentType;
    private ASN1OctetString encryptedContent;

    public EncryptedContentInfo(DERObjectIdentifier contentType, AlgorithmIdentifier contentEncryptionAlgorithm, ASN1OctetString encryptedContent) {
        this.contentType = contentType;
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        this.encryptedContent = encryptedContent;
    }

    public EncryptedContentInfo(ASN1Sequence seq) {
        this.contentType = (DERObjectIdentifier) seq.getObjectAt(0);
        this.contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            this.encryptedContent = ASN1OctetString.getInstance((ASN1TaggedObject) seq.getObjectAt(2), false);
        }
    }

    public static EncryptedContentInfo getInstance(Object obj) {
        if (obj == null || (obj instanceof EncryptedContentInfo)) {
            return (EncryptedContentInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new EncryptedContentInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid EncryptedContentInfo: " + obj.getClass().getName());
    }

    public DERObjectIdentifier getContentType() {
        return this.contentType;
    }

    public AlgorithmIdentifier getContentEncryptionAlgorithm() {
        return this.contentEncryptionAlgorithm;
    }

    public ASN1OctetString getEncryptedContent() {
        return this.encryptedContent;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.contentType);
        v.add(this.contentEncryptionAlgorithm);
        if (this.encryptedContent != null) {
            v.add(new BERTaggedObject(false, 0, this.encryptedContent));
        }
        return new BERSequence(v);
    }
}
