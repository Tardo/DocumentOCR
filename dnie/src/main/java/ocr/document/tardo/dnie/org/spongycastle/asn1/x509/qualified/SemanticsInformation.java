package org.spongycastle.asn1.x509.qualified;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.GeneralName;

public class SemanticsInformation extends ASN1Encodable {
    GeneralName[] nameRegistrationAuthorities;
    DERObjectIdentifier semanticsIdentifier;

    public static SemanticsInformation getInstance(Object obj) {
        if (obj == null || (obj instanceof SemanticsInformation)) {
            return (SemanticsInformation) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new SemanticsInformation(ASN1Sequence.getInstance(obj));
        }
        throw new IllegalArgumentException("unknown object in getInstance");
    }

    public SemanticsInformation(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        if (seq.size() < 1) {
            throw new IllegalArgumentException("no objects in SemanticsInformation");
        }
        Object object = e.nextElement();
        if (object instanceof DERObjectIdentifier) {
            this.semanticsIdentifier = DERObjectIdentifier.getInstance(object);
            if (e.hasMoreElements()) {
                object = e.nextElement();
            } else {
                object = null;
            }
        }
        if (object != null) {
            ASN1Sequence generalNameSeq = ASN1Sequence.getInstance(object);
            this.nameRegistrationAuthorities = new GeneralName[generalNameSeq.size()];
            for (int i = 0; i < generalNameSeq.size(); i++) {
                this.nameRegistrationAuthorities[i] = GeneralName.getInstance(generalNameSeq.getObjectAt(i));
            }
        }
    }

    public SemanticsInformation(DERObjectIdentifier semanticsIdentifier, GeneralName[] generalNames) {
        this.semanticsIdentifier = semanticsIdentifier;
        this.nameRegistrationAuthorities = generalNames;
    }

    public SemanticsInformation(DERObjectIdentifier semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
        this.nameRegistrationAuthorities = null;
    }

    public SemanticsInformation(GeneralName[] generalNames) {
        this.semanticsIdentifier = null;
        this.nameRegistrationAuthorities = generalNames;
    }

    public DERObjectIdentifier getSemanticsIdentifier() {
        return this.semanticsIdentifier;
    }

    public GeneralName[] getNameRegistrationAuthorities() {
        return this.nameRegistrationAuthorities;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        if (this.semanticsIdentifier != null) {
            seq.add(this.semanticsIdentifier);
        }
        if (this.nameRegistrationAuthorities != null) {
            ASN1EncodableVector seqname = new ASN1EncodableVector();
            for (DEREncodable add : this.nameRegistrationAuthorities) {
                seqname.add(add);
            }
            seq.add(new DERSequence(seqname));
        }
        return new DERSequence(seq);
    }
}
