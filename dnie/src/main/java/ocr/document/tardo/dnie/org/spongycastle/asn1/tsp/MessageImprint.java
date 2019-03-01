package org.spongycastle.asn1.tsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class MessageImprint extends ASN1Encodable {
    AlgorithmIdentifier hashAlgorithm;
    byte[] hashedMessage;

    public static MessageImprint getInstance(Object o) {
        if (o == null || (o instanceof MessageImprint)) {
            return (MessageImprint) o;
        }
        if (o instanceof ASN1Sequence) {
            return new MessageImprint((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Bad object in factory.");
    }

    public MessageImprint(ASN1Sequence seq) {
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.hashedMessage = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
    }

    public MessageImprint(AlgorithmIdentifier hashAlgorithm, byte[] hashedMessage) {
        this.hashAlgorithm = hashAlgorithm;
        this.hashedMessage = hashedMessage;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public byte[] getHashedMessage() {
        return this.hashedMessage;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.hashAlgorithm);
        v.add(new DEROctetString(this.hashedMessage));
        return new DERSequence(v);
    }
}
