package org.spongycastle.ocsp;

import java.security.cert.X509Extension;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.ocsp.Request;
import org.spongycastle.asn1.x509.X509Extensions;

public class Req implements X509Extension {
    private Request req;

    public Req(Request req) {
        this.req = req;
    }

    public CertificateID getCertID() {
        return new CertificateID(this.req.getReqCert());
    }

    public X509Extensions getSingleRequestExtensions() {
        return this.req.getSingleRequestExtensions();
    }

    public boolean hasUnsupportedCriticalExtension() {
        Set extns = getCriticalExtensionOIDs();
        if (extns == null || extns.isEmpty()) {
            return false;
        }
        return true;
    }

    private Set getExtensionOIDs(boolean critical) {
        Set set = new HashSet();
        X509Extensions extensions = getSingleRequestExtensions();
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
        X509Extensions exts = getSingleRequestExtensions();
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
