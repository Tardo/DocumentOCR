package org.spongycastle.asn1.pkcs;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class PBES2Algorithms extends AlgorithmIdentifier implements PKCSObjectIdentifiers {
    private KeyDerivationFunc func;
    private DERObjectIdentifier objectId;
    private EncryptionScheme scheme;

    public PBES2Algorithms(ASN1Sequence obj) {
        super(obj);
        Enumeration e = obj.getObjects();
        this.objectId = (DERObjectIdentifier) e.nextElement();
        e = ((ASN1Sequence) e.nextElement()).getObjects();
        ASN1Sequence funcSeq = (ASN1Sequence) e.nextElement();
        if (funcSeq.getObjectAt(0).equals(id_PBKDF2)) {
            this.func = new KeyDerivationFunc(id_PBKDF2, PBKDF2Params.getInstance(funcSeq.getObjectAt(1)));
        } else {
            this.func = new KeyDerivationFunc(funcSeq);
        }
        this.scheme = new EncryptionScheme((ASN1Sequence) e.nextElement());
    }

    public DERObjectIdentifier getObjectId() {
        return this.objectId;
    }

    public KeyDerivationFunc getKeyDerivationFunc() {
        return this.func;
    }

    public EncryptionScheme getEncryptionScheme() {
        return this.scheme;
    }

    public DERObject getDERObject() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        ASN1EncodableVector subV = new ASN1EncodableVector();
        v.add(this.objectId);
        subV.add(this.func);
        subV.add(this.scheme);
        v.add(new DERSequence(subV));
        return new DERSequence(v);
    }
}
