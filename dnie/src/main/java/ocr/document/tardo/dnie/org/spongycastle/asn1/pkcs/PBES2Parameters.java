package org.spongycastle.asn1.pkcs;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class PBES2Parameters extends ASN1Encodable implements PKCSObjectIdentifiers {
    private KeyDerivationFunc func;
    private EncryptionScheme scheme;

    public static PBES2Parameters getInstance(Object obj) {
        if (obj == null || (obj instanceof PBES2Parameters)) {
            return (PBES2Parameters) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new PBES2Parameters((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public PBES2Parameters(ASN1Sequence obj) {
        Enumeration e = obj.getObjects();
        ASN1Sequence funcSeq = ASN1Sequence.getInstance(((DEREncodable) e.nextElement()).getDERObject());
        if (funcSeq.getObjectAt(0).equals(id_PBKDF2)) {
            this.func = new KeyDerivationFunc(id_PBKDF2, PBKDF2Params.getInstance(funcSeq.getObjectAt(1)));
        } else {
            this.func = new KeyDerivationFunc(funcSeq);
        }
        this.scheme = (EncryptionScheme) EncryptionScheme.getInstance(e.nextElement());
    }

    public KeyDerivationFunc getKeyDerivationFunc() {
        return this.func;
    }

    public EncryptionScheme getEncryptionScheme() {
        return this.scheme;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.func);
        v.add(this.scheme);
        return new DERSequence(v);
    }
}
