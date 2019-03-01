package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;

public class V2AttributeCertificateInfoGenerator {
    private ASN1EncodableVector attributes = new ASN1EncodableVector();
    private DERGeneralizedTime endDate;
    private X509Extensions extensions;
    private Holder holder;
    private AttCertIssuer issuer;
    private DERBitString issuerUniqueID;
    private DERInteger serialNumber;
    private AlgorithmIdentifier signature;
    private DERGeneralizedTime startDate;
    private DERInteger version = new DERInteger(1);

    public void setHolder(Holder holder) {
        this.holder = holder;
    }

    public void addAttribute(String oid, ASN1Encodable value) {
        this.attributes.add(new Attribute(new DERObjectIdentifier(oid), new DERSet((DEREncodable) value)));
    }

    public void addAttribute(Attribute attribute) {
        this.attributes.add(attribute);
    }

    public void setSerialNumber(DERInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public void setSignature(AlgorithmIdentifier signature) {
        this.signature = signature;
    }

    public void setIssuer(AttCertIssuer issuer) {
        this.issuer = issuer;
    }

    public void setStartDate(DERGeneralizedTime startDate) {
        this.startDate = startDate;
    }

    public void setEndDate(DERGeneralizedTime endDate) {
        this.endDate = endDate;
    }

    public void setIssuerUniqueID(DERBitString issuerUniqueID) {
        this.issuerUniqueID = issuerUniqueID;
    }

    public void setExtensions(X509Extensions extensions) {
        this.extensions = extensions;
    }

    public AttributeCertificateInfo generateAttributeCertificateInfo() {
        if (this.serialNumber == null || this.signature == null || this.issuer == null || this.startDate == null || this.endDate == null || this.holder == null || this.attributes == null) {
            throw new IllegalStateException("not all mandatory fields set in V2 AttributeCertificateInfo generator");
        }
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        v.add(this.holder);
        v.add(this.issuer);
        v.add(this.signature);
        v.add(this.serialNumber);
        v.add(new AttCertValidityPeriod(this.startDate, this.endDate));
        v.add(new DERSequence(this.attributes));
        if (this.issuerUniqueID != null) {
            v.add(this.issuerUniqueID);
        }
        if (this.extensions != null) {
            v.add(this.extensions);
        }
        return new AttributeCertificateInfo(new DERSequence(v));
    }
}
