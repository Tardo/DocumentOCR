package org.spongycastle.asn1.pkcs;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;

public class SignedData extends ASN1Encodable implements PKCSObjectIdentifiers {
    private ASN1Set certificates;
    private ContentInfo contentInfo;
    private ASN1Set crls;
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
        throw new IllegalArgumentException("unknown object in factory: " + o);
    }

    public SignedData(DERInteger _version, ASN1Set _digestAlgorithms, ContentInfo _contentInfo, ASN1Set _certificates, ASN1Set _crls, ASN1Set _signerInfos) {
        this.version = _version;
        this.digestAlgorithms = _digestAlgorithms;
        this.contentInfo = _contentInfo;
        this.certificates = _certificates;
        this.crls = _crls;
        this.signerInfos = _signerInfos;
    }

    public SignedData(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.version = (DERInteger) e.nextElement();
        this.digestAlgorithms = (ASN1Set) e.nextElement();
        this.contentInfo = ContentInfo.getInstance(e.nextElement());
        while (e.hasMoreElements()) {
            DERObject o = (DERObject) e.nextElement();
            if (o instanceof DERTaggedObject) {
                DERTaggedObject tagged = (DERTaggedObject) o;
                switch (tagged.getTagNo()) {
                    case 0:
                        this.certificates = ASN1Set.getInstance(tagged, false);
                        break;
                    case 1:
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

    public ContentInfo getContentInfo() {
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
            v.add(new DERTaggedObject(false, 0, this.certificates));
        }
        if (this.crls != null) {
            v.add(new DERTaggedObject(false, 1, this.crls));
        }
        v.add(this.signerInfos);
        return new BERSequence(v);
    }
}
