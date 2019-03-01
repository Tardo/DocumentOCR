package org.spongycastle.asn1.cmp;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.crmf.CertId;
import org.spongycastle.asn1.x509.CertificateList;

public class RevRepContent extends ASN1Encodable {
    private ASN1Sequence crls;
    private ASN1Sequence revCerts;
    private ASN1Sequence status;

    private RevRepContent(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        this.status = ASN1Sequence.getInstance(en.nextElement());
        while (en.hasMoreElements()) {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(en.nextElement());
            if (tObj.getTagNo() == 0) {
                this.revCerts = ASN1Sequence.getInstance(tObj, true);
            } else {
                this.crls = ASN1Sequence.getInstance(tObj, true);
            }
        }
    }

    public static RevRepContent getInstance(Object o) {
        if (o instanceof RevRepContent) {
            return (RevRepContent) o;
        }
        if (o instanceof ASN1Sequence) {
            return new RevRepContent((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public PKIStatusInfo[] getStatus() {
        PKIStatusInfo[] results = new PKIStatusInfo[this.status.size()];
        for (int i = 0; i != results.length; i++) {
            results[i] = PKIStatusInfo.getInstance(this.status.getObjectAt(i));
        }
        return results;
    }

    public CertId[] getRevCerts() {
        if (this.revCerts == null) {
            return null;
        }
        CertId[] results = new CertId[this.revCerts.size()];
        for (int i = 0; i != results.length; i++) {
            results[i] = CertId.getInstance(this.revCerts.getObjectAt(i));
        }
        return results;
    }

    public CertificateList[] getCrls() {
        if (this.crls == null) {
            return null;
        }
        CertificateList[] results = new CertificateList[this.crls.size()];
        for (int i = 0; i != results.length; i++) {
            results[i] = CertificateList.getInstance(this.crls.getObjectAt(i));
        }
        return results;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.status);
        addOptional(v, 0, this.revCerts);
        addOptional(v, 1, this.crls);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }
}
