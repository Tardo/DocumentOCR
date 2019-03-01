package org.bouncycastle.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertStore;
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
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.X509Extensions;

public class BasicOCSPResp implements X509Extension {
    X509Certificate[] chain = null;
    ResponseData data;
    BasicOCSPResponse resp;

    public BasicOCSPResp(BasicOCSPResponse basicOCSPResponse) {
        this.resp = basicOCSPResponse;
        this.data = basicOCSPResponse.getTbsResponseData();
    }

    private List getCertList(String str) throws OCSPException, NoSuchProviderException {
        List arrayList = new ArrayList();
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ASN1OutputStream aSN1OutputStream = new ASN1OutputStream(byteArrayOutputStream);
        try {
            CertificateFactory createX509CertificateFactory = OCSPUtil.createX509CertificateFactory(str);
            ASN1Sequence certs = this.resp.getCerts();
            if (certs != null) {
                Enumeration objects = certs.getObjects();
                while (objects.hasMoreElements()) {
                    try {
                        aSN1OutputStream.writeObject((ASN1Encodable) objects.nextElement());
                        arrayList.add(createX509CertificateFactory.generateCertificate(new ByteArrayInputStream(byteArrayOutputStream.toByteArray())));
                        byteArrayOutputStream.reset();
                    } catch (Exception e) {
                        throw new OCSPException("can't re-encode certificate!", e);
                    } catch (Exception e2) {
                        throw new OCSPException("can't re-encode certificate!", e2);
                    }
                }
            }
            return arrayList;
        } catch (Exception e22) {
            throw new OCSPException("can't get certificate factory.", e22);
        }
    }

    private Set getExtensionOIDs(boolean z) {
        Set hashSet = new HashSet();
        X509Extensions responseExtensions = getResponseExtensions();
        if (responseExtensions != null) {
            Enumeration oids = responseExtensions.oids();
            while (oids.hasMoreElements()) {
                DERObjectIdentifier dERObjectIdentifier = (DERObjectIdentifier) oids.nextElement();
                if (z == responseExtensions.getExtension(dERObjectIdentifier).isCritical()) {
                    hashSet.add(dERObjectIdentifier.getId());
                }
            }
        }
        return hashSet;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof BasicOCSPResp)) {
            return false;
        }
        return this.resp.equals(((BasicOCSPResp) obj).resp);
    }

    public CertStore getCertificates(String str, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, OCSPException {
        try {
            return OCSPUtil.createCertStoreInstance(str, new CollectionCertStoreParameters(getCertList(str2)), str2);
        } catch (Exception e) {
            throw new OCSPException("can't setup the CertStore", e);
        }
    }

    public X509Certificate[] getCerts(String str) throws OCSPException, NoSuchProviderException {
        List certList = getCertList(str);
        return (X509Certificate[]) certList.toArray(new X509Certificate[certList.size()]);
    }

    public Set getCriticalExtensionOIDs() {
        return getExtensionOIDs(true);
    }

    public byte[] getEncoded() throws IOException {
        return this.resp.getEncoded();
    }

    public byte[] getExtensionValue(String str) {
        X509Extensions responseExtensions = getResponseExtensions();
        if (responseExtensions != null) {
            org.bouncycastle.asn1.x509.X509Extension extension = responseExtensions.getExtension(new DERObjectIdentifier(str));
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

    public Date getProducedAt() {
        try {
            return this.data.getProducedAt().getDate();
        } catch (ParseException e) {
            throw new IllegalStateException("ParseException:" + e.getMessage());
        }
    }

    public RespID getResponderId() {
        return new RespID(this.data.getResponderID());
    }

    public RespData getResponseData() {
        return new RespData(this.resp.getTbsResponseData());
    }

    public X509Extensions getResponseExtensions() {
        return X509Extensions.getInstance(this.data.getResponseExtensions());
    }

    public SingleResp[] getResponses() {
        ASN1Sequence responses = this.data.getResponses();
        SingleResp[] singleRespArr = new SingleResp[responses.size()];
        for (int i = 0; i != singleRespArr.length; i++) {
            singleRespArr[i] = new SingleResp(SingleResponse.getInstance(responses.getObjectAt(i)));
        }
        return singleRespArr;
    }

    public byte[] getSignature() {
        return this.resp.getSignature().getBytes();
    }

    public String getSignatureAlgName() {
        return OCSPUtil.getAlgorithmName(this.resp.getSignatureAlgorithm().getObjectId());
    }

    public String getSignatureAlgOID() {
        return this.resp.getSignatureAlgorithm().getObjectId().getId();
    }

    public byte[] getTBSResponseData() throws OCSPException {
        try {
            return this.resp.getTbsResponseData().getEncoded();
        } catch (Exception e) {
            throw new OCSPException("problem encoding tbsResponseData", e);
        }
    }

    public int getVersion() {
        return this.data.getVersion().getValue().intValue() + 1;
    }

    public boolean hasUnsupportedCriticalExtension() {
        Set criticalExtensionOIDs = getCriticalExtensionOIDs();
        return (criticalExtensionOIDs == null || criticalExtensionOIDs.isEmpty()) ? false : true;
    }

    public int hashCode() {
        return this.resp.hashCode();
    }

    public boolean verify(PublicKey publicKey, String str) throws OCSPException, NoSuchProviderException {
        try {
            Signature createSignatureInstance = OCSPUtil.createSignatureInstance(getSignatureAlgName(), str);
            createSignatureInstance.initVerify(publicKey);
            createSignatureInstance.update(this.resp.getTbsResponseData().getEncoded("DER"));
            return createSignatureInstance.verify(getSignature());
        } catch (NoSuchProviderException e) {
            throw e;
        } catch (Exception e2) {
            throw new OCSPException("exception processing sig: " + e2, e2);
        }
    }
}
