package org.spongycastle.ocsp;

import java.security.cert.X509Extension;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.ocsp.ResponseData;
import org.spongycastle.asn1.ocsp.SingleResponse;
import org.spongycastle.asn1.x509.X509Extensions;

public class RespData implements X509Extension {
    ResponseData data;

    public RespData(ResponseData data) {
        this.data = data;
    }

    public int getVersion() {
        return this.data.getVersion().getValue().intValue() + 1;
    }

    public RespID getResponderId() {
        return new RespID(this.data.getResponderID());
    }

    public Date getProducedAt() {
        try {
            return this.data.getProducedAt().getDate();
        } catch (ParseException e) {
            throw new IllegalStateException("ParseException:" + e.getMessage());
        }
    }

    public SingleResp[] getResponses() {
        ASN1Sequence s = this.data.getResponses();
        SingleResp[] rs = new SingleResp[s.size()];
        for (int i = 0; i != rs.length; i++) {
            rs[i] = new SingleResp(SingleResponse.getInstance(s.getObjectAt(i)));
        }
        return rs;
    }

    public X509Extensions getResponseExtensions() {
        return this.data.getResponseExtensions();
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
        X509Extensions extensions = getResponseExtensions();
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
        X509Extensions exts = getResponseExtensions();
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
