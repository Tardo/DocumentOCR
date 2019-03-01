package org.bouncycastle.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extensions;

public class OCSPReq implements X509Extension {
    private OCSPRequest req;

    public OCSPReq(InputStream inputStream) throws IOException {
        this(new ASN1InputStream(inputStream));
    }

    private OCSPReq(ASN1InputStream aSN1InputStream) throws IOException {
        try {
            this.req = OCSPRequest.getInstance(aSN1InputStream.readObject());
        } catch (IllegalArgumentException e) {
            throw new IOException("malformed request: " + e.getMessage());
        } catch (ClassCastException e2) {
            throw new IOException("malformed request: " + e2.getMessage());
        }
    }

    public OCSPReq(OCSPRequest oCSPRequest) {
        this.req = oCSPRequest;
    }

    public OCSPReq(byte[] bArr) throws IOException {
        this(new ASN1InputStream(bArr));
    }

    private List getCertList(String str) throws OCSPException, NoSuchProviderException {
        List arrayList = new ArrayList();
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ASN1OutputStream aSN1OutputStream = new ASN1OutputStream(byteArrayOutputStream);
        try {
            CertificateFactory createX509CertificateFactory = OCSPUtil.createX509CertificateFactory(str);
            ASN1Sequence certs = this.req.getOptionalSignature().getCerts();
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
        X509Extensions requestExtensions = getRequestExtensions();
        if (requestExtensions != null) {
            Enumeration oids = requestExtensions.oids();
            while (oids.hasMoreElements()) {
                ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) oids.nextElement();
                if (z == requestExtensions.getExtension(aSN1ObjectIdentifier).isCritical()) {
                    hashSet.add(aSN1ObjectIdentifier.getId());
                }
            }
        }
        return hashSet;
    }

    public CertStore getCertificates(String str, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, OCSPException {
        if (!isSigned()) {
            return null;
        }
        try {
            return OCSPUtil.createCertStoreInstance(str, new CollectionCertStoreParameters(getCertList(str2)), str2);
        } catch (Exception e) {
            throw new OCSPException("can't setup the CertStore", e);
        }
    }

    public X509Certificate[] getCerts(String str) throws OCSPException, NoSuchProviderException {
        if (!isSigned()) {
            return null;
        }
        List certList = getCertList(str);
        return (X509Certificate[]) certList.toArray(new X509Certificate[certList.size()]);
    }

    public Set getCriticalExtensionOIDs() {
        return getExtensionOIDs(true);
    }

    public byte[] getEncoded() throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        new ASN1OutputStream(byteArrayOutputStream).writeObject(this.req);
        return byteArrayOutputStream.toByteArray();
    }

    public byte[] getExtensionValue(String str) {
        X509Extensions requestExtensions = getRequestExtensions();
        if (requestExtensions != null) {
            org.bouncycastle.asn1.x509.X509Extension extension = requestExtensions.getExtension(new ASN1ObjectIdentifier(str));
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

    public X509Extensions getRequestExtensions() {
        return X509Extensions.getInstance(this.req.getTbsRequest().getRequestExtensions());
    }

    public Req[] getRequestList() {
        ASN1Sequence requestList = this.req.getTbsRequest().getRequestList();
        Req[] reqArr = new Req[requestList.size()];
        for (int i = 0; i != reqArr.length; i++) {
            reqArr[i] = new Req(Request.getInstance(requestList.getObjectAt(i)));
        }
        return reqArr;
    }

    public GeneralName getRequestorName() {
        return GeneralName.getInstance(this.req.getTbsRequest().getRequestorName());
    }

    public byte[] getSignature() {
        return !isSigned() ? null : this.req.getOptionalSignature().getSignature().getBytes();
    }

    public String getSignatureAlgOID() {
        return !isSigned() ? null : this.req.getOptionalSignature().getSignatureAlgorithm().getObjectId().getId();
    }

    public byte[] getTBSRequest() throws OCSPException {
        try {
            return this.req.getTbsRequest().getEncoded();
        } catch (Exception e) {
            throw new OCSPException("problem encoding tbsRequest", e);
        }
    }

    public int getVersion() {
        return this.req.getTbsRequest().getVersion().getValue().intValue() + 1;
    }

    public boolean hasUnsupportedCriticalExtension() {
        Set criticalExtensionOIDs = getCriticalExtensionOIDs();
        return (criticalExtensionOIDs == null || criticalExtensionOIDs.isEmpty()) ? false : true;
    }

    public boolean isSigned() {
        return this.req.getOptionalSignature() != null;
    }

    public boolean verify(PublicKey publicKey, String str) throws OCSPException, NoSuchProviderException {
        if (isSigned()) {
            try {
                Signature createSignatureInstance = OCSPUtil.createSignatureInstance(getSignatureAlgOID(), str);
                createSignatureInstance.initVerify(publicKey);
                OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                new ASN1OutputStream(byteArrayOutputStream).writeObject(this.req.getTbsRequest());
                createSignatureInstance.update(byteArrayOutputStream.toByteArray());
                return createSignatureInstance.verify(getSignature());
            } catch (NoSuchProviderException e) {
                throw e;
            } catch (Exception e2) {
                throw new OCSPException("exception processing sig: " + e2, e2);
            }
        }
        throw new OCSPException("attempt to verify signature on unsigned object");
    }
}
