package org.spongycastle.asn1.crmf;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.X509Extensions;

public class CertTemplate extends ASN1Encodable {
    private X509Extensions extensions;
    private X500Name issuer;
    private DERBitString issuerUID;
    private SubjectPublicKeyInfo publicKey;
    private ASN1Sequence seq;
    private DERInteger serialNumber;
    private AlgorithmIdentifier signingAlg;
    private X500Name subject;
    private DERBitString subjectUID;
    private OptionalValidity validity;
    private DERInteger version;

    private CertTemplate(ASN1Sequence seq) {
        this.seq = seq;
        Enumeration en = seq.getObjects();
        while (en.hasMoreElements()) {
            ASN1TaggedObject tObj = (ASN1TaggedObject) en.nextElement();
            switch (tObj.getTagNo()) {
                case 0:
                    this.version = DERInteger.getInstance(tObj, false);
                    break;
                case 1:
                    this.serialNumber = DERInteger.getInstance(tObj, false);
                    break;
                case 2:
                    this.signingAlg = AlgorithmIdentifier.getInstance(tObj, false);
                    break;
                case 3:
                    this.issuer = X500Name.getInstance(tObj, true);
                    break;
                case 4:
                    this.validity = OptionalValidity.getInstance(ASN1Sequence.getInstance(tObj, false));
                    break;
                case 5:
                    this.subject = X500Name.getInstance(tObj, true);
                    break;
                case 6:
                    this.publicKey = SubjectPublicKeyInfo.getInstance(tObj, false);
                    break;
                case 7:
                    this.issuerUID = DERBitString.getInstance(tObj, false);
                    break;
                case 8:
                    this.subjectUID = DERBitString.getInstance(tObj, false);
                    break;
                case 9:
                    this.extensions = X509Extensions.getInstance(tObj, false);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag: " + tObj.getTagNo());
            }
        }
    }

    public static CertTemplate getInstance(Object o) {
        if (o instanceof CertTemplate) {
            return (CertTemplate) o;
        }
        if (o != null) {
            return new CertTemplate(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public int getVersion() {
        return this.version.getValue().intValue();
    }

    public DERInteger getSerialNumber() {
        return this.serialNumber;
    }

    public AlgorithmIdentifier getSigningAlg() {
        return this.signingAlg;
    }

    public X500Name getIssuer() {
        return this.issuer;
    }

    public OptionalValidity getValidity() {
        return this.validity;
    }

    public X500Name getSubject() {
        return this.subject;
    }

    public SubjectPublicKeyInfo getPublicKey() {
        return this.publicKey;
    }

    public void setPublicKey(SubjectPublicKeyInfo spki) {
        this.publicKey = spki;
    }

    public DERBitString getIssuerUID() {
        return this.issuerUID;
    }

    public DERBitString getSubjectUID() {
        return this.subjectUID;
    }

    public X509Extensions getExtensions() {
        return this.extensions;
    }

    public DERObject toASN1Object() {
        return this.seq;
    }
}
