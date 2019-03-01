package org.bouncycastle.ocsp;

import java.security.cert.X509Extension;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.x509.X509Extensions;

public class Req implements X509Extension {
    private Request req;

    public Req(Request request) {
        this.req = request;
    }

    private Set getExtensionOIDs(boolean z) {
        Set hashSet = new HashSet();
        X509Extensions singleRequestExtensions = getSingleRequestExtensions();
        if (singleRequestExtensions != null) {
            Enumeration oids = singleRequestExtensions.oids();
            while (oids.hasMoreElements()) {
                DERObjectIdentifier dERObjectIdentifier = (DERObjectIdentifier) oids.nextElement();
                if (z == singleRequestExtensions.getExtension(dERObjectIdentifier).isCritical()) {
                    hashSet.add(dERObjectIdentifier.getId());
                }
            }
        }
        return hashSet;
    }

    public CertificateID getCertID() {
        return new CertificateID(this.req.getReqCert());
    }

    public Set getCriticalExtensionOIDs() {
        return getExtensionOIDs(true);
    }

    public byte[] getExtensionValue(String str) {
        X509Extensions singleRequestExtensions = getSingleRequestExtensions();
        if (singleRequestExtensions != null) {
            org.bouncycastle.asn1.x509.X509Extension extension = singleRequestExtensions.getExtension(new DERObjectIdentifier(str));
            if (extension != null) {
                try {
                    return extension.getValue().getEncoded("DER");
                } catch (Exception e) {
                    throw new RuntimeException("error encoding " + e.toString());
                }
            }
        }
        return null;
    }

    public Set getNonCriticalExtensionOIDs() {
        return getExtensionOIDs(false);
    }

    public X509Extensions getSingleRequestExtensions() {
        return X509Extensions.getInstance(this.req.getSingleRequestExtensions());
    }

    public boolean hasUnsupportedCriticalExtension() {
        Set criticalExtensionOIDs = getCriticalExtensionOIDs();
        return (criticalExtensionOIDs == null || criticalExtensionOIDs.isEmpty()) ? false : true;
    }
}
