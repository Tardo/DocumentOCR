package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;

public class POPOSigningKeyInput extends ASN1Encodable {
    private SubjectPublicKeyInfo publicKey;
    private PKMACValue publicKeyMAC;
    private GeneralName sender;

    private POPOSigningKeyInput(ASN1Sequence seq) {
        ASN1Encodable authInfo = (ASN1Encodable) seq.getObjectAt(0);
        if (authInfo instanceof ASN1TaggedObject) {
            ASN1TaggedObject tagObj = (ASN1TaggedObject) authInfo;
            if (tagObj.getTagNo() != 0) {
                throw new IllegalArgumentException("Unknown authInfo tag: " + tagObj.getTagNo());
            }
            this.sender = GeneralName.getInstance(tagObj.getObject());
        } else {
            this.publicKeyMAC = PKMACValue.getInstance(authInfo);
        }
        this.publicKey = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(1));
    }

    public static POPOSigningKeyInput getInstance(Object o) {
        if (o instanceof POPOSigningKeyInput) {
            return (POPOSigningKeyInput) o;
        }
        if (o instanceof ASN1Sequence) {
            return new POPOSigningKeyInput((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public POPOSigningKeyInput(GeneralName sender, SubjectPublicKeyInfo spki) {
        this.sender = sender;
        this.publicKey = spki;
    }

    public POPOSigningKeyInput(PKMACValue pkmac, SubjectPublicKeyInfo spki) {
        this.publicKeyMAC = pkmac;
        this.publicKey = spki;
    }

    public GeneralName getSender() {
        return this.sender;
    }

    public PKMACValue getPublicKeyMAC() {
        return this.publicKeyMAC;
    }

    public SubjectPublicKeyInfo getPublicKey() {
        return this.publicKey;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.sender != null) {
            v.add(new DERTaggedObject(false, 0, this.sender));
        } else {
            v.add(this.publicKeyMAC);
        }
        v.add(this.publicKey);
        return new DERSequence(v);
    }
}
