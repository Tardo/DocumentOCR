package de.tsenger.androsmex.asn1;

import de.tsenger.androsmex.tools.HexString;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class ChipAuthenticationPublicKeyInfo extends ASN1Encodable {
    private SubjectPublicKeyInfo capk = null;
    private DERInteger keyId = null;
    private DERObjectIdentifier protocol = null;

    public ChipAuthenticationPublicKeyInfo(DERSequence seq) {
        this.protocol = (DERObjectIdentifier) seq.getObjectAt(0);
        this.capk = new SubjectPublicKeyInfo((DERSequence) seq.getObjectAt(1));
        if (seq.size() == 3) {
            this.keyId = (DERInteger) seq.getObjectAt(2);
        }
    }

    public DERObjectIdentifier getProtocol() {
        return this.protocol;
    }

    public SubjectPublicKeyInfo getPublicKey() {
        return this.capk;
    }

    public int getKeyId() {
        return this.keyId.getPositiveValue().intValue();
    }

    public String toString() {
        return "ChipAuthenticationPublicKeyInfo \n\tprotocol: " + getProtocol() + "\n\tSubjectPublicKeyInfo: \n\t\t" + "Algorithm: " + getPublicKey().getAlgorithm().getAlgorithm() + "\n\t\t" + "AmPublicKey:" + HexString.bufferToHex(getPublicKey().getPublicKey()) + "\n\tKeyID " + getKeyId() + "\n";
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(this.protocol);
        vec.add(this.capk);
        if (this.keyId != null) {
            vec.add(this.keyId);
        }
        return new DERSequence(vec);
    }
}
