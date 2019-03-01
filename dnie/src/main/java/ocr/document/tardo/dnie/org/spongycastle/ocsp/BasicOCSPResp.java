package org.spongycastle.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.spongycastle.asn1.ASN1OutputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.ocsp.BasicOCSPResponse;
import org.spongycastle.asn1.ocsp.ResponseData;
import org.spongycastle.asn1.ocsp.SingleResponse;
import org.spongycastle.asn1.x509.X509Extensions;

public class BasicOCSPResp implements X509Extension {
    X509Certificate[] chain = null;
    ResponseData data;
    BasicOCSPResponse resp;

    public BasicOCSPResp(BasicOCSPResponse resp) {
        this.resp = resp;
        this.data = resp.getTbsResponseData();
    }

    public byte[] getTBSResponseData() throws OCSPException {
        try {
            return this.resp.getTbsResponseData().getEncoded();
        } catch (IOException e) {
            throw new OCSPException("problem encoding tbsResponseData", e);
        }
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

    public String getSignatureAlgName() {
        return OCSPUtil.getAlgorithmName(this.resp.getSignatureAlgorithm().getObjectId());
    }

    public String getSignatureAlgOID() {
        return this.resp.getSignatureAlgorithm().getObjectId().getId();
    }

    public RespData getResponseData() {
        return new RespData(this.resp.getTbsResponseData());
    }

    public byte[] getSignature() {
        return this.resp.getSignature().getBytes();
    }

    private List getCertList(String provider) throws OCSPException, NoSuchProviderException {
        List certs = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = new ASN1OutputStream(bOut);
        try {
            CertificateFactory cf = OCSPUtil.createX509CertificateFactory(provider);
            ASN1Sequence s = this.resp.getCerts();
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
        List certs = getCertList(provider);
        return (X509Certificate[]) certs.toArray(new X509Certificate[certs.size()]);
    }

    public CertStore getCertificates(String type, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, OCSPException {
        try {
            return OCSPUtil.createCertStoreInstance(type, new CollectionCertStoreParameters(getCertList(provider)), provider);
        } catch (InvalidAlgorithmParameterException e) {
            throw new OCSPException("can't setup the CertStore", e);
        }
    }

    public boolean verify(PublicKey key, String sigProvider) throws OCSPException, NoSuchProviderException {
        try {
            Signature signature = OCSPUtil.createSignatureInstance(getSignatureAlgName(), sigProvider);
            signature.initVerify(key);
            signature.update(this.resp.getTbsResponseData().getEncoded("DER"));
            return signature.verify(getSignature());
        } catch (NoSuchProviderException e) {
            throw e;
        } catch (Exception e2) {
            throw new OCSPException("exception processing sig: " + e2, e2);
        }
    }

    public byte[] getEncoded() throws IOException {
        return this.resp.getEncoded();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof BasicOCSPResp)) {
            return false;
        }
        return this.resp.equals(((BasicOCSPResp) o).resp);
    }

    public int hashCode() {
        return this.resp.hashCode();
    }
}
