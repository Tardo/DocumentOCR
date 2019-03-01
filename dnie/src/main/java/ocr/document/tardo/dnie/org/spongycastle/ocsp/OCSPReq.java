package org.spongycastle.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1OutputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ocsp.OCSPRequest;
import org.spongycastle.asn1.ocsp.Request;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.X509Extensions;

public class OCSPReq implements X509Extension {
    private OCSPRequest req;

    public OCSPReq(OCSPRequest req) {
        this.req = req;
    }

    public OCSPReq(byte[] req) throws IOException {
        this(new ASN1InputStream(req));
    }

    public OCSPReq(InputStream in) throws IOException {
        this(new ASN1InputStream(in));
    }

    private OCSPReq(ASN1InputStream aIn) throws IOException {
        try {
            this.req = OCSPRequest.getInstance(aIn.readObject());
        } catch (IllegalArgumentException e) {
            throw new IOException("malformed request: " + e.getMessage());
        } catch (ClassCastException e2) {
            throw new IOException("malformed request: " + e2.getMessage());
        }
    }

    public byte[] getTBSRequest() throws OCSPException {
        try {
            return this.req.getTbsRequest().getEncoded();
        } catch (IOException e) {
            throw new OCSPException("problem encoding tbsRequest", e);
        }
    }

    public int getVersion() {
        return this.req.getTbsRequest().getVersion().getValue().intValue() + 1;
    }

    public GeneralName getRequestorName() {
        return GeneralName.getInstance(this.req.getTbsRequest().getRequestorName());
    }

    public Req[] getRequestList() {
        ASN1Sequence seq = this.req.getTbsRequest().getRequestList();
        Req[] requests = new Req[seq.size()];
        for (int i = 0; i != requests.length; i++) {
            requests[i] = new Req(Request.getInstance(seq.getObjectAt(i)));
        }
        return requests;
    }

    public X509Extensions getRequestExtensions() {
        return X509Extensions.getInstance(this.req.getTbsRequest().getRequestExtensions());
    }

    public String getSignatureAlgOID() {
        if (isSigned()) {
            return this.req.getOptionalSignature().getSignatureAlgorithm().getObjectId().getId();
        }
        return null;
    }

    public byte[] getSignature() {
        if (isSigned()) {
            return this.req.getOptionalSignature().getSignature().getBytes();
        }
        return null;
    }

    private List getCertList(String provider) throws OCSPException, NoSuchProviderException {
        List certs = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = new ASN1OutputStream(bOut);
        try {
            CertificateFactory cf = OCSPUtil.createX509CertificateFactory(provider);
            ASN1Sequence s = this.req.getOptionalSignature().getCerts();
            if (s != null) {
                Enumeration e = s.getObjects();
                while (e.hasMoreElements()) {
                    try {
                        aOut.writeObject(e.nextElement());
                        certs.add(cf.generateCertificate(new ByteArrayInputStream(bOut.toByteArray())));
                        bOut.reset();
                    } catch (IOException ex) {
                        throw new OCSPException("can't re-encode certificate!", ex);
                    } catch (CertificateException ex2) {
                        throw new OCSPException("can't re-encode certificate!", ex2);
                    }
                }
            }
            return certs;
        } catch (CertificateException ex22) {
            throw new OCSPException("can't get certificate factory.", ex22);
        }
    }

    public X509Certificate[] getCerts(String provider) throws OCSPException, NoSuchProviderException {
        if (!isSigned()) {
            return null;
        }
        List certs = getCertList(provider);
        return (X509Certificate[]) certs.toArray(new X509Certificate[certs.size()]);
    }

    public CertStore getCertificates(String type, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, OCSPException {
        if (!isSigned()) {
            return null;
        }
        try {
            return OCSPUtil.createCertStoreInstance(type, new CollectionCertStoreParameters(getCertList(provider)), provider);
        } catch (InvalidAlgorithmParameterException e) {
            throw new OCSPException("can't setup the CertStore", e);
        }
    }

    public boolean isSigned() {
        return this.req.getOptionalSignature() != null;
    }

    public boolean verify(PublicKey key, String sigProvider) throws OCSPException, NoSuchProviderException {
        if (isSigned()) {
            try {
                Signature signature = OCSPUtil.createSignatureInstance(getSignatureAlgOID(), sigProvider);
                signature.initVerify(key);
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                new ASN1OutputStream(bOut).writeObject(this.req.getTbsRequest());
                signature.update(bOut.toByteArray());
                return signature.verify(getSignature());
            } catch (NoSuchProviderException e) {
                throw e;
            } catch (Exception e2) {
                throw new OCSPException("exception processing sig: " + e2, e2);
            }
        }
        throw new OCSPException("attempt to verify signature on unsigned object");
    }

    public byte[] getEncoded() throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new ASN1OutputStream(bOut).writeObject(this.req);
        return bOut.toByteArray();
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
        X509Extensions extensions = getRequestExtensions();
        if (extensions != null) {
            Enumeration e = extensions.oids();
            while (e.hasMoreElements()) {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
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
        X509Extensions exts = getRequestExtensions();
        if (exts != null) {
            org.spongycastle.asn1.x509.X509Extension ext = exts.getExtension(new ASN1ObjectIdentifier(oid));
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
