package org.spongycastle.asn1.esf;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.ocsp.BasicOCSPResponse;
import org.spongycastle.asn1.x509.CertificateList;

public class RevocationValues extends ASN1Encodable {
    private ASN1Sequence crlVals;
    private ASN1Sequence ocspVals;
    private OtherRevVals otherRevVals;

    public static RevocationValues getInstance(Object obj) {
        if (obj == null || (obj instanceof RevocationValues)) {
            return (RevocationValues) obj;
        }
        if (obj != null) {
            return new RevocationValues(ASN1Sequence.getInstance(obj));
        }
        throw new IllegalArgumentException("null value in getInstance");
    }

    private RevocationValues(ASN1Sequence seq) {
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            DERTaggedObject o = (DERTaggedObject) e.nextElement();
            switch (o.getTagNo()) {
                case 0:
                    ASN1Sequence crlValsSeq = (ASN1Sequence) o.getObject();
                    Enumeration crlValsEnum = crlValsSeq.getObjects();
                    while (crlValsEnum.hasMoreElements()) {
                        CertificateList.getInstance(crlValsEnum.nextElement());
                    }
                    this.crlVals = crlValsSeq;
                    break;
                case 1:
                    ASN1Sequence ocspValsSeq = (ASN1Sequence) o.getObject();
                    Enumeration ocspValsEnum = ocspValsSeq.getObjects();
                    while (ocspValsEnum.hasMoreElements()) {
                        BasicOCSPResponse.getInstance(ocspValsEnum.nextElement());
                    }
                    this.ocspVals = ocspValsSeq;
                    break;
                case 2:
                    this.otherRevVals = OtherRevVals.getInstance(o.getObject());
                    break;
                default:
                    throw new IllegalArgumentException("invalid tag: " + o.getTagNo());
            }
        }
    }

    public RevocationValues(CertificateList[] crlVals, BasicOCSPResponse[] ocspVals, OtherRevVals otherRevVals) {
        if (crlVals != null) {
            this.crlVals = new DERSequence((ASN1Encodable[]) crlVals);
        }
        if (ocspVals != null) {
            this.ocspVals = new DERSequence((ASN1Encodable[]) ocspVals);
        }
        this.otherRevVals = otherRevVals;
    }

    public CertificateList[] getCrlVals() {
        if (this.crlVals == null) {
            return new CertificateList[0];
        }
        CertificateList[] result = new CertificateList[this.crlVals.size()];
        for (int idx = 0; idx < result.length; idx++) {
            result[idx] = CertificateList.getInstance(this.crlVals.getObjectAt(idx));
        }
        return result;
    }

    public BasicOCSPResponse[] getOcspVals() {
        if (this.ocspVals == null) {
            return new BasicOCSPResponse[0];
        }
        BasicOCSPResponse[] result = new BasicOCSPResponse[this.ocspVals.size()];
        for (int idx = 0; idx < result.length; idx++) {
            result[idx] = BasicOCSPResponse.getInstance(this.ocspVals.getObjectAt(idx));
        }
        return result;
    }

    public OtherRevVals getOtherRevVals() {
        return this.otherRevVals;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.crlVals != null) {
            v.add(new DERTaggedObject(true, 0, this.crlVals));
        }
        if (this.ocspVals != null) {
            v.add(new DERTaggedObject(true, 1, this.ocspVals));
        }
        if (this.otherRevVals != null) {
            v.add(new DERTaggedObject(true, 2, this.otherRevVals.toASN1Object()));
        }
        return new DERSequence(v);
    }
}
