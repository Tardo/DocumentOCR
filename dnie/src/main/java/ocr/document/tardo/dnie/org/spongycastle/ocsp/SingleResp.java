package org.spongycastle.ocsp;

import java.security.cert.X509Extension;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.ocsp.CertStatus;
import org.spongycastle.asn1.ocsp.RevokedInfo;
import org.spongycastle.asn1.ocsp.SingleResponse;
import org.spongycastle.asn1.x509.X509Extensions;

public class SingleResp implements X509Extension {
    SingleResponse resp;

    public SingleResp(SingleResponse resp) {
        this.resp = resp;
    }

    public CertificateID getCertID() {
        return new CertificateID(this.resp.getCertID());
    }

    public Object getCertStatus() {
        CertStatus s = this.resp.getCertStatus();
        if (s.getTagNo() == 0) {
            return null;
        }
        if (s.getTagNo() == 1) {
            return new RevokedStatus(RevokedInfo.getInstance(s.getStatus()));
        }
        return new UnknownStatus();
    }

    public Date getThisUpdate() {
        try {
            return this.resp.getThisUpdate().getDate();
        } catch (ParseException e) {
            throw new IllegalStateException("ParseException: " + e.getMessage());
        }
    }

    public Date getNextUpdate() {
        if (this.resp.getNextUpdate() == null) {
            return null;
        }
        try {
            return this.resp.getNextUpdate().getDate();
        } catch (ParseException e) {
            throw new IllegalStateException("ParseException: " + e.getMessage());
        }
    }

    public X509Extensions getSingleExtensions() {
        return this.resp.getSingleExtensions();
    }

    public boolean hasUnsupportedCriticalExtension() {
        Set extns = getCriticalExtensionOIDs();
        return (extns == null || extns.isEmpty()) ? false : true;
    }

    private Set getExtensionOIDs(boolean critical) {
        Set set = new HashSet();
        X509Extensions extensions = getSingleExtensions();
        if (extensions != null) {
            Enumeration e = extensions.oids();
            while (e.hasMoreElements()) {
                DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                if (critical == extensions.getExtension(oid).isCritical()) {
                    set.add(oid.getId());
                }
            }
        }
        return set;
    }

    public Set getCriticalExtensionOIDs() {
        return getExtensionOIDs(true);
    }

    public Set getNonCriticalExtensionOIDs() {
        return getExtensionOIDs(false);
    }

    public byte[] getExtensionValue(String oid) {
        X509Extensions exts = getSingleExtensions();
        if (exts != null) {
            org.spongycastle.asn1.x509.X509Extension ext = exts.getExtension(new DERObjectIdentifier(oid));
            if (ext != null) {
                try {
                    return ext.getValue().getEncoded("DER");
                } catch (Exception e) {
                    throw new RuntimeException("error encoding " + e.toString());
                }
            }
        }
        return null;
    }
}
