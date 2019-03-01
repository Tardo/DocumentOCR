package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.DERUTCTime;
import org.spongycastle.asn1.x500.X500Name;

public class V1TBSCertificateGenerator {
    Time endDate;
    X509Name issuer;
    DERInteger serialNumber;
    AlgorithmIdentifier signature;
    Time startDate;
    X509Name subject;
    SubjectPublicKeyInfo subjectPublicKeyInfo;
    DERTaggedObject version = new DERTaggedObject(0, new DERInteger(0));

    public void setSerialNumber(DERInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public void setSignature(AlgorithmIdentifier signature) {
        this.signature = signature;
    }

    public void setIssuer(X509Name issuer) {
        this.issuer = issuer;
    }

    public void setIssuer(X500Name issuer) {
        this.issuer = X509Name.getInstance(issuer.getDERObject());
    }

    public void setStartDate(Time startDate) {
        this.startDate = startDate;
    }

    public void setStartDate(DERUTCTime startDate) {
        this.startDate = new Time((DERObject) startDate);
    }

    public void setEndDate(Time endDate) {
        this.endDate = endDate;
    }

    public void setEndDate(DERUTCTime endDate) {
        this.endDate = new Time((DERObject) endDate);
    }

    public void setSubject(X509Name subject) {
        this.subject = subject;
    }

    public void setSubject(X500Name subject) {
        this.subject = X509Name.getInstance(subject.getDERObject());
    }

    public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo pubKeyInfo) {
        this.subjectPublicKeyInfo = pubKeyInfo;
    }

    public TBSCertificateStructure generateTBSCertificate() {
        if (this.serialNumber == null || this.signature == null || this.issuer == null || this.startDate == null || this.endDate == null || this.subject == null || this.subjectPublicKeyInfo == null) {
            throw new IllegalStateException("not all mandatory fields set in V1 TBScertificate generator");
        }
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(this.serialNumber);
        seq.add(this.signature);
        seq.add(this.issuer);
        ASN1EncodableVector validity = new ASN1EncodableVector();
        validity.add(this.startDate);
        validity.add(this.endDate);
        seq.add(new DERSequence(validity));
        seq.add(this.subject);
        seq.add(this.subjectPublicKeyInfo);
        return new TBSCertificateStructure(new DERSequence(seq));
    }
}
