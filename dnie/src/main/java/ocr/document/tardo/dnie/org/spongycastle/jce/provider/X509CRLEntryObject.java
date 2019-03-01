package org.spongycastle.jce.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREnumerated;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.util.ASN1Dump;
import org.spongycastle.asn1.x509.CRLReason;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.GeneralNames;
import org.spongycastle.asn1.x509.TBSCertList.CRLEntry;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.asn1.x509.X509Extensions;
import org.spongycastle.x509.extension.X509ExtensionUtil;

public class X509CRLEntryObject extends X509CRLEntry {
    /* renamed from: c */
    private CRLEntry f179c;
    private X500Principal certificateIssuer = loadCertificateIssuer();
    private int hashValue;
    private boolean isHashValueSet;
    private boolean isIndirect;
    private X500Principal previousCertificateIssuer;

    public X509CRLEntryObject(CRLEntry c) {
        this.f179c = c;
    }

    public X509CRLEntryObject(CRLEntry c, boolean isIndirect, X500Principal previousCertificateIssuer) {
        this.f179c = c;
        this.isIndirect = isIndirect;
        this.previousCertificateIssuer = previousCertificateIssuer;
    }

    public boolean hasUnsupportedCriticalExtension() {
        Set extns = getCriticalExtensionOIDs();
        return (extns == null || extns.isEmpty()) ? false : true;
    }

    private X500Principal loadCertificateIssuer() {
        if (!this.isIndirect) {
            return null;
        }
        byte[] ext = getExtensionValue(X509Extensions.CertificateIssuer.getId());
        if (ext == null) {
            return this.previousCertificateIssuer;
        }
        try {
            GeneralName[] names = GeneralNames.getInstance(X509ExtensionUtil.fromExtensionValue(ext)).getNames();
            for (int i = 0; i < names.length; i++) {
                if (names[i].getTagNo() == 4) {
                    return new X500Principal(names[i].getName().getDERObject().getDEREncoded());
                }
            }
            return null;
        } catch (IOException e) {
            return null;
        }
    }

    public X500Principal getCertificateIssuer() {
        return this.certificateIssuer;
    }

    private Set getExtensionOIDs(boolean critical) {
        X509Extensions extensions = this.f179c.getExtensions();
        if (extensions == null) {
            return null;
        }
        Set hashSet = new HashSet();
        Enumeration e = extensions.oids();
        while (e.hasMoreElements()) {
            DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
            if (critical == extensions.getExtension(oid).isCritical()) {
                hashSet.add(oid.getId());
            }
        }
        return hashSet;
    }

    public Set getCriticalExtensionOIDs() {
        return getExtensionOIDs(true);
    }

    public Set getNonCriticalExtensionOIDs() {
        return getExtensionOIDs(false);
    }

    public byte[] getExtensionValue(String oid) {
        X509Extensions exts = this.f179c.getExtensions();
        if (exts != null) {
            X509Extension ext = exts.getExtension(new DERObjectIdentifier(oid));
            if (ext != null) {
                try {
                    return ext.getValue().getEncoded();
                } catch (Exception e) {
                    throw new RuntimeException("error encoding " + e.toString());
                }
            }
        }
        return null;
    }

    public int hashCode() {
        if (!this.isHashValueSet) {
            this.hashValue = super.hashCode();
            this.isHashValueSet = true;
        }
        return this.hashValue;
    }

    public byte[] getEncoded() throws CRLException {
        try {
            return this.f179c.getEncoded("DER");
        } catch (IOException e) {
            throw new CRLException(e.toString());
        }
    }

    public BigInteger getSerialNumber() {
        return this.f179c.getUserCertificate().getValue();
    }

    public Date getRevocationDate() {
        return this.f179c.getRevocationDate().getDate();
    }

    public boolean hasExtensions() {
        return this.f179c.getExtensions() != null;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append("      userCertificate: ").append(getSerialNumber()).append(nl);
        buf.append("       revocationDate: ").append(getRevocationDate()).append(nl);
        buf.append("       certificateIssuer: ").append(getCertificateIssuer()).append(nl);
        X509Extensions extensions = this.f179c.getExtensions();
        if (extensions != null) {
            Enumeration e = extensions.oids();
            if (e.hasMoreElements()) {
                buf.append("   crlEntryExtensions:").append(nl);
                while (e.hasMoreElements()) {
                    DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                    X509Extension ext = extensions.getExtension(oid);
                    if (ext.getValue() != null) {
                        ASN1InputStream dIn = new ASN1InputStream(ext.getValue().getOctets());
                        buf.append("                       critical(").append(ext.isCritical()).append(") ");
                        try {
                            if (oid.equals(X509Extensions.ReasonCode)) {
                                buf.append(new CRLReason(DEREnumerated.getInstance(dIn.readObject()))).append(nl);
                            } else if (oid.equals(X509Extensions.CertificateIssuer)) {
                                buf.append("Certificate issuer: ").append(new GeneralNames((ASN1Sequence) dIn.readObject())).append(nl);
                            } else {
                                buf.append(oid.getId());
                                buf.append(" value = ").append(ASN1Dump.dumpAsString(dIn.readObject())).append(nl);
                            }
                        } catch (Exception e2) {
                            buf.append(oid.getId());
                            buf.append(" value = ").append("*****").append(nl);
                        }
                    } else {
                        buf.append(nl);
                    }
                }
            }
        }
        return buf.toString();
    }
}
