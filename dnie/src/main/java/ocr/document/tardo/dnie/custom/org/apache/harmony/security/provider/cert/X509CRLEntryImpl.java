package custom.org.apache.harmony.security.provider.cert;

import custom.org.apache.harmony.security.x509.Extension;
import custom.org.apache.harmony.security.x509.Extensions;
import custom.org.apache.harmony.security.x509.TBSCertList.RevokedCertificate;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

public class X509CRLEntryImpl extends X509CRLEntry {
    private byte[] encoding;
    private final Extensions extensions;
    private final X500Principal issuer;
    private final RevokedCertificate rcert;

    public X509CRLEntryImpl(RevokedCertificate rcert, X500Principal issuer) {
        this.rcert = rcert;
        this.extensions = rcert.getCrlEntryExtensions();
        this.issuer = issuer;
    }

    public byte[] getEncoded() throws CRLException {
        if (this.encoding == null) {
            this.encoding = this.rcert.getEncoded();
        }
        byte[] result = new byte[this.encoding.length];
        System.arraycopy(this.encoding, 0, result, 0, this.encoding.length);
        return result;
    }

    public BigInteger getSerialNumber() {
        return this.rcert.getUserCertificate();
    }

    public X500Principal getCertificateIssuer() {
        return this.issuer;
    }

    public Date getRevocationDate() {
        return this.rcert.getRevocationDate();
    }

    public boolean hasExtensions() {
        return (this.extensions == null || this.extensions.size() == 0) ? false : true;
    }

    public String toString() {
        return "X509CRLEntryImpl: " + this.rcert.toString();
    }

    public Set getNonCriticalExtensionOIDs() {
        if (this.extensions == null) {
            return null;
        }
        return this.extensions.getNonCriticalExtensions();
    }

    public Set getCriticalExtensionOIDs() {
        if (this.extensions == null) {
            return null;
        }
        return this.extensions.getCriticalExtensions();
    }

    public byte[] getExtensionValue(String oid) {
        if (this.extensions == null) {
            return null;
        }
        Extension ext = this.extensions.getExtensionByOID(oid);
        if (ext != null) {
            return ext.getRawExtnValue();
        }
        return null;
    }

    public boolean hasUnsupportedCriticalExtension() {
        if (this.extensions == null) {
            return false;
        }
        return this.extensions.hasUnsupportedCritical();
    }
}
