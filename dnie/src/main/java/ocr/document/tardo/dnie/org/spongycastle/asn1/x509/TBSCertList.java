package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.DERUTCTime;

public class TBSCertList extends ASN1Encodable {
    X509Extensions crlExtensions;
    X509Name issuer;
    Time nextUpdate;
    ASN1Sequence revokedCertificates;
    ASN1Sequence seq;
    AlgorithmIdentifier signature;
    Time thisUpdate;
    DERInteger version;

    private class EmptyEnumeration implements Enumeration {
        private EmptyEnumeration() {
        }

        public boolean hasMoreElements() {
            return false;
        }

        public Object nextElement() {
            return null;
        }
    }

    private class RevokedCertificatesEnumeration implements Enumeration {
        private final Enumeration en;

        RevokedCertificatesEnumeration(Enumeration en) {
            this.en = en;
        }

        public boolean hasMoreElements() {
            return this.en.hasMoreElements();
        }

        public Object nextElement() {
            return new CRLEntry(ASN1Sequence.getInstance(this.en.nextElement()));
        }
    }

    public static class CRLEntry extends ASN1Encodable {
        X509Extensions crlEntryExtensions;
        Time revocationDate;
        ASN1Sequence seq;
        DERInteger userCertificate;

        public CRLEntry(ASN1Sequence seq) {
            if (seq.size() < 2 || seq.size() > 3) {
                throw new IllegalArgumentException("Bad sequence size: " + seq.size());
            }
            this.seq = seq;
            this.userCertificate = DERInteger.getInstance(seq.getObjectAt(0));
            this.revocationDate = Time.getInstance(seq.getObjectAt(1));
        }

        public DERInteger getUserCertificate() {
            return this.userCertificate;
        }

        public Time getRevocationDate() {
            return this.revocationDate;
        }

        public X509Extensions getExtensions() {
            if (this.crlEntryExtensions == null && this.seq.size() == 3) {
                this.crlEntryExtensions = X509Extensions.getInstance(this.seq.getObjectAt(2));
            }
            return this.crlEntryExtensions;
        }

        public DERObject toASN1Object() {
            return this.seq;
        }
    }

    public static TBSCertList getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static TBSCertList getInstance(Object obj) {
        if (obj instanceof TBSCertList) {
            return (TBSCertList) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new TBSCertList((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public TBSCertList(ASN1Sequence seq) {
        if (seq.size() < 3 || seq.size() > 7) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        int seqPos;
        int seqPos2 = 0;
        this.seq = seq;
        if (seq.getObjectAt(0) instanceof DERInteger) {
            seqPos = 0 + 1;
            this.version = DERInteger.getInstance(seq.getObjectAt(0));
            seqPos2 = seqPos;
        } else {
            this.version = new DERInteger(0);
        }
        seqPos = seqPos2 + 1;
        this.signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(seqPos2));
        seqPos2 = seqPos + 1;
        this.issuer = X509Name.getInstance(seq.getObjectAt(seqPos));
        seqPos = seqPos2 + 1;
        this.thisUpdate = Time.getInstance(seq.getObjectAt(seqPos2));
        if (seqPos >= seq.size() || !((seq.getObjectAt(seqPos) instanceof DERUTCTime) || (seq.getObjectAt(seqPos) instanceof DERGeneralizedTime) || (seq.getObjectAt(seqPos) instanceof Time))) {
            seqPos2 = seqPos;
        } else {
            seqPos2 = seqPos + 1;
            this.nextUpdate = Time.getInstance(seq.getObjectAt(seqPos));
        }
        if (seqPos2 < seq.size() && !(seq.getObjectAt(seqPos2) instanceof DERTaggedObject)) {
            seqPos = seqPos2 + 1;
            this.revokedCertificates = ASN1Sequence.getInstance(seq.getObjectAt(seqPos2));
            seqPos2 = seqPos;
        }
        if (seqPos2 < seq.size() && (seq.getObjectAt(seqPos2) instanceof DERTaggedObject)) {
            this.crlExtensions = X509Extensions.getInstance(seq.getObjectAt(seqPos2));
        }
    }

    public int getVersion() {
        return this.version.getValue().intValue() + 1;
    }

    public DERInteger getVersionNumber() {
        return this.version;
    }

    public AlgorithmIdentifier getSignature() {
        return this.signature;
    }

    public X509Name getIssuer() {
        return this.issuer;
    }

    public Time getThisUpdate() {
        return this.thisUpdate;
    }

    public Time getNextUpdate() {
        return this.nextUpdate;
    }

    public CRLEntry[] getRevokedCertificates() {
        if (this.revokedCertificates == null) {
            return new CRLEntry[0];
        }
        CRLEntry[] entries = new CRLEntry[this.revokedCertificates.size()];
        for (int i = 0; i < entries.length; i++) {
            entries[i] = new CRLEntry(ASN1Sequence.getInstance(this.revokedCertificates.getObjectAt(i)));
        }
        return entries;
    }

    public Enumeration getRevokedCertificateEnumeration() {
        if (this.revokedCertificates == null) {
            return new EmptyEnumeration();
        }
        return new RevokedCertificatesEnumeration(this.revokedCertificates.getObjects());
    }

    public X509Extensions getExtensions() {
        return this.crlExtensions;
    }

    public DERObject toASN1Object() {
        return this.seq;
    }
}
