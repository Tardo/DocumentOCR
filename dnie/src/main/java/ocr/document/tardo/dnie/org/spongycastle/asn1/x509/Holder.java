package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class Holder extends ASN1Encodable {
    IssuerSerial baseCertificateID;
    GeneralNames entityName;
    ObjectDigestInfo objectDigestInfo;
    private int version = 1;

    public static Holder getInstance(Object obj) {
        if (obj instanceof Holder) {
            return (Holder) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new Holder((ASN1Sequence) obj);
        }
        if (obj instanceof ASN1TaggedObject) {
            return new Holder((ASN1TaggedObject) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public Holder(ASN1TaggedObject tagObj) {
        switch (tagObj.getTagNo()) {
            case 0:
                this.baseCertificateID = IssuerSerial.getInstance(tagObj, false);
                break;
            case 1:
                this.entityName = GeneralNames.getInstance(tagObj, false);
                break;
            default:
                throw new IllegalArgumentException("unknown tag in Holder");
        }
        this.version = 0;
    }

    public Holder(ASN1Sequence seq) {
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        for (int i = 0; i != seq.size(); i++) {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
            switch (tObj.getTagNo()) {
                case 0:
                    this.baseCertificateID = IssuerSerial.getInstance(tObj, false);
                    break;
                case 1:
                    this.entityName = GeneralNames.getInstance(tObj, false);
                    break;
                case 2:
                    this.objectDigestInfo = ObjectDigestInfo.getInstance(tObj, false);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag in Holder");
            }
        }
        this.version = 1;
    }

    public Holder(IssuerSerial baseCertificateID) {
        this.baseCertificateID = baseCertificateID;
    }

    public Holder(IssuerSerial baseCertificateID, int version) {
        this.baseCertificateID = baseCertificateID;
        this.version = version;
    }

    public int getVersion() {
        return this.version;
    }

    public Holder(GeneralNames entityName) {
        this.entityName = entityName;
    }

    public Holder(GeneralNames entityName, int version) {
        this.entityName = entityName;
        this.version = version;
    }

    public Holder(ObjectDigestInfo objectDigestInfo) {
        this.objectDigestInfo = objectDigestInfo;
    }

    public IssuerSerial getBaseCertificateID() {
        return this.baseCertificateID;
    }

    public GeneralNames getEntityName() {
        return this.entityName;
    }

    public ObjectDigestInfo getObjectDigestInfo() {
        return this.objectDigestInfo;
    }

    public DERObject toASN1Object() {
        if (this.version == 1) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            if (this.baseCertificateID != null) {
                v.add(new DERTaggedObject(false, 0, this.baseCertificateID));
            }
            if (this.entityName != null) {
                v.add(new DERTaggedObject(false, 1, this.entityName));
            }
            if (this.objectDigestInfo != null) {
                v.add(new DERTaggedObject(false, 2, this.objectDigestInfo));
            }
            return new DERSequence(v);
        } else if (this.entityName != null) {
            return new DERTaggedObject(false, 1, this.entityName);
        } else {
            return new DERTaggedObject(false, 0, this.baseCertificateID);
        }
    }
}
