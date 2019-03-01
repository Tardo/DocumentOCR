package org.spongycastle.asn1.cms;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.BERSet;
import org.spongycastle.asn1.BERTaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERTaggedObject;

public class SignedData extends ASN1Encodable {
    private ASN1Set certificates;
    private boolean certsBer;
    private ContentInfo contentInfo;
    private ASN1Set crls;
    private boolean crlsBer;
    private ASN1Set digestAlgorithms;
    private ASN1Set signerInfos;
    private DERInteger version;

    public static SignedData getInstance(Object o) {
        if (o instanceof SignedData) {
            return (SignedData) o;
        }
        if (o instanceof ASN1Sequence) {
            return new SignedData((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
    }

    public SignedData(ASN1Set digestAlgorithms, ContentInfo contentInfo, ASN1Set certificates, ASN1Set crls, ASN1Set signerInfos) {
        this.version = calculateVersion(contentInfo.getContentType(), certificates, crls, signerInfos);
        this.digestAlgorithms = digestAlgorithms;
        this.contentInfo = contentInfo;
        this.certificates = certificates;
        this.crls = crls;
        this.signerInfos = signerInfos;
        this.crlsBer = crls instanceof BERSet;
        this.certsBer = certificates instanceof BERSet;
    }

    private DERInteger calculateVersion(DERObjectIdentifier contentOid, ASN1Set certs, ASN1Set crls, ASN1Set signerInfs) {
        Enumeration en;
        boolean otherCert = false;
        boolean otherCrl = false;
        boolean attrCertV1Found = false;
        boolean attrCertV2Found = false;
        if (certs != null) {
            en = certs.getObjects();
            while (en.hasMoreElements()) {
                ASN1TaggedObject obj = en.nextElement();
                if (obj instanceof ASN1TaggedObject) {
                    ASN1TaggedObject tagged = obj;
                    if (tagged.getTagNo() == 1) {
                        attrCertV1Found = true;
                    } else if (tagged.getTagNo() == 2) {
                        attrCertV2Found = true;
                    } else if (tagged.getTagNo() == 3) {
                        otherCert = true;
                    }
                }
            }
        }
        if (otherCert) {
            return new DERInteger(5);
        }
        if (crls != null) {
            en = crls.getObjects();
            while (en.hasMoreElements()) {
                if (en.nextElement() instanceof ASN1TaggedObject) {
                    otherCrl = true;
                }
            }
        }
        if (otherCrl) {
            return new DERInteger(5);
        }
        if (attrCertV2Found) {
            return new DERInteger(4);
        }
        if (attrCertV1Found) {
            return new DERInteger(3);
        }
        if (checkForVersion3(signerInfs)) {
            return new DERInteger(3);
        }
        if (CMSObjectIdentifiers.data.equals(contentOid)) {
            return new DERInteger(1);
        }
        return new DERInteger(3);
    }

    private boolean checkForVersion3(ASN1Set signerInfs) {
        Enumeration e = signerInfs.getObjects();
        while (e.hasMoreElements()) {
            if (SignerInfo.getInstance(e.nextElement()).getVersion().getValue().intValue() == 3) {
                return true;
            }
        }
        return false;
    }

    public SignedData(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.version = (DERInteger) e.nextElement();
        this.digestAlgorithms = (ASN1Set) e.nextElement();
        this.contentInfo = ContentInfo.getInstance(e.nextElement());
        while (e.hasMoreElements()) {
            DERObject o = (DERObject) e.nextElement();
            if (o instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) o;
                switch (tagged.getTagNo()) {
                    case 0:
                        this.certsBer = tagged instanceof BERTaggedObject;
                        this.certificates = ASN1Set.getInstance(tagged, false);
                        break;
                    case 1:
                        this.crlsBer = tagged instanceof BERTaggedObject;
                        this.crls = ASN1Set.getInstance(tagged, false);
                        break;
                    default:
                        throw new IllegalArgumentException("unknown tag value " + tagged.getTagNo());
                }
            }
            this.signerInfos = (ASN1Set) o;
        }
    }

    public DERInteger getVersion() {
        return this.version;
    }

    public ASN1Set getDigestAlgorithms() {
        return this.digestAlgorithms;
    }

    public ContentInfo getEncapContentInfo() {
        return this.contentInfo;
    }

    public ASN1Set getCertificates() {
        return this.certificates;
    }

    public ASN1Set getCRLs() {
        return this.crls;
    }

    public ASN1Set getSignerInfos() {
        return this.signerInfos;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        v.add(this.digestAlgorithms);
        v.add(this.contentInfo);
        if (this.certificates != null) {
            if (this.certsBer) {
                v.add(new BERTaggedObject(false, 0, this.certificates));
            } else {
                v.add(new DERTaggedObject(false, 0, this.certificates));
            }
        }
        if (this.crls != null) {
            if (this.crlsBer) {
                v.add(new BERTaggedObject(false, 1, this.crls));
            } else {
                v.add(new DERTaggedObject(false, 1, this.crls));
            }
        }
        v.add(this.signerInfos);
        return new BERSequence(v);
    }
}
