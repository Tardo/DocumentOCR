package org.spongycastle.asn1.x509;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.DERUTCTime;
import org.spongycastle.asn1.x500.X500Name;

public class V2TBSCertListGenerator {
    private Vector crlentries = null;
    X509Extensions extensions = null;
    X509Name issuer;
    Time nextUpdate = null;
    AlgorithmIdentifier signature;
    Time thisUpdate;
    DERInteger version = new DERInteger(1);

    public void setSignature(AlgorithmIdentifier signature) {
        this.signature = signature;
    }

    public void setIssuer(X509Name issuer) {
        this.issuer = issuer;
    }

    public void setIssuer(X500Name issuer) {
        this.issuer = X509Name.getInstance(issuer);
    }

    public void setThisUpdate(DERUTCTime thisUpdate) {
        this.thisUpdate = new Time((DERObject) thisUpdate);
    }

    public void setNextUpdate(DERUTCTime nextUpdate) {
        this.nextUpdate = new Time((DERObject) nextUpdate);
    }

    public void setThisUpdate(Time thisUpdate) {
        this.thisUpdate = thisUpdate;
    }

    public void setNextUpdate(Time nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    public void addCRLEntry(ASN1Sequence crlEntry) {
        if (this.crlentries == null) {
            this.crlentries = new Vector();
        }
        this.crlentries.addElement(crlEntry);
    }

    public void addCRLEntry(DERInteger userCertificate, DERUTCTime revocationDate, int reason) {
        addCRLEntry(userCertificate, new Time((DERObject) revocationDate), reason);
    }

    public void addCRLEntry(DERInteger userCertificate, Time revocationDate, int reason) {
        addCRLEntry(userCertificate, revocationDate, reason, null);
    }

    public void addCRLEntry(DERInteger userCertificate, Time revocationDate, int reason, DERGeneralizedTime invalidityDate) {
        Vector extOids = new Vector();
        Vector extValues = new Vector();
        if (reason != 0) {
            CRLReason crlReason = new CRLReason(reason);
            try {
                extOids.addElement(X509Extension.reasonCode);
                extValues.addElement(new X509Extension(false, new DEROctetString(crlReason.getEncoded())));
            } catch (IOException e) {
                throw new IllegalArgumentException("error encoding reason: " + e);
            }
        }
        if (invalidityDate != null) {
            try {
                extOids.addElement(X509Extension.invalidityDate);
                extValues.addElement(new X509Extension(false, new DEROctetString(invalidityDate.getEncoded())));
            } catch (IOException e2) {
                throw new IllegalArgumentException("error encoding invalidityDate: " + e2);
            }
        }
        if (extOids.size() != 0) {
            addCRLEntry(userCertificate, revocationDate, new X509Extensions(extOids, extValues));
        } else {
            addCRLEntry(userCertificate, revocationDate, null);
        }
    }

    public void addCRLEntry(DERInteger userCertificate, Time revocationDate, X509Extensions extensions) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(userCertificate);
        v.add(revocationDate);
        if (extensions != null) {
            v.add(extensions);
        }
        addCRLEntry(new DERSequence(v));
    }

    public void setExtensions(X509Extensions extensions) {
        this.extensions = extensions;
    }

    public TBSCertList generateTBSCertList() {
        if (this.signature == null || this.issuer == null || this.thisUpdate == null) {
            throw new IllegalStateException("Not all mandatory fields set in V2 TBSCertList generator.");
        }
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        v.add(this.signature);
        v.add(this.issuer);
        v.add(this.thisUpdate);
        if (this.nextUpdate != null) {
            v.add(this.nextUpdate);
        }
        if (this.crlentries != null) {
            ASN1EncodableVector certs = new ASN1EncodableVector();
            Enumeration it = this.crlentries.elements();
            while (it.hasMoreElements()) {
                certs.add((ASN1Sequence) it.nextElement());
            }
            v.add(new DERSequence(certs));
        }
        if (this.extensions != null) {
            v.add(new DERTaggedObject(0, this.extensions));
        }
        return new TBSCertList(new DERSequence(v));
    }
}
