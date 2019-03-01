package org.bouncycastle.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;

public class OCSPReqGenerator {
    private List list = new ArrayList();
    private X509Extensions requestExtensions = null;
    private GeneralName requestorName = null;

    private class RequestObject {
        CertificateID certId;
        X509Extensions extensions;

        public RequestObject(CertificateID certificateID, X509Extensions x509Extensions) {
            this.certId = certificateID;
            this.extensions = x509Extensions;
        }

        public Request toRequest() throws Exception {
            return new Request(this.certId.toASN1Object(), Extensions.getInstance(this.extensions));
        }
    }

    private OCSPReq generateRequest(DERObjectIdentifier dERObjectIdentifier, PrivateKey privateKey, X509Certificate[] x509CertificateArr, String str, SecureRandom secureRandom) throws OCSPException, NoSuchProviderException {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        for (RequestObject toRequest : this.list) {
            try {
                aSN1EncodableVector.add(toRequest.toRequest());
            } catch (Exception e) {
                throw new OCSPException("exception creating Request", e);
            }
        }
        Object tBSRequest = new TBSRequest(this.requestorName, new DERSequence(aSN1EncodableVector), this.requestExtensions);
        Signature signature = null;
        if (dERObjectIdentifier != null) {
            if (this.requestorName == null) {
                throw new OCSPException("requestorName must be specified if request is signed.");
            }
            try {
                java.security.Signature createSignatureInstance = OCSPUtil.createSignatureInstance(dERObjectIdentifier.getId(), str);
                if (secureRandom != null) {
                    createSignatureInstance.initSign(privateKey, secureRandom);
                } else {
                    createSignatureInstance.initSign(privateKey);
                }
                try {
                    OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    new ASN1OutputStream(byteArrayOutputStream).writeObject(tBSRequest);
                    createSignatureInstance.update(byteArrayOutputStream.toByteArray());
                    DERBitString dERBitString = new DERBitString(createSignatureInstance.sign());
                    AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(dERObjectIdentifier, DERNull.INSTANCE);
                    if (x509CertificateArr == null || x509CertificateArr.length <= 0) {
                        signature = new Signature(algorithmIdentifier, dERBitString);
                    } else {
                        ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
                        int i = 0;
                        while (i != x509CertificateArr.length) {
                            try {
                                aSN1EncodableVector2.add(new X509CertificateStructure((ASN1Sequence) ASN1Primitive.fromByteArray(x509CertificateArr[i].getEncoded())));
                                i++;
                            } catch (Exception e2) {
                                throw new OCSPException("error processing certs", e2);
                            } catch (Exception e22) {
                                throw new OCSPException("error encoding certs", e22);
                            }
                        }
                        signature = new Signature(algorithmIdentifier, dERBitString, new DERSequence(aSN1EncodableVector2));
                    }
                } catch (Exception e222) {
                    throw new OCSPException("exception processing TBSRequest: " + e222, e222);
                }
            } catch (NoSuchProviderException e3) {
                throw e3;
            } catch (Exception e2222) {
                throw new OCSPException("exception creating signature: " + e2222, e2222);
            }
        }
        return new OCSPReq(new OCSPRequest(tBSRequest, signature));
    }

    public void addRequest(CertificateID certificateID) {
        this.list.add(new RequestObject(certificateID, null));
    }

    public void addRequest(CertificateID certificateID, X509Extensions x509Extensions) {
        this.list.add(new RequestObject(certificateID, x509Extensions));
    }

    public OCSPReq generate() throws OCSPException {
        try {
            return generateRequest(null, null, null, null, null);
        } catch (Exception e) {
            throw new OCSPException("no provider! - " + e, e);
        }
    }

    public OCSPReq generate(String str, PrivateKey privateKey, X509Certificate[] x509CertificateArr, String str2) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
        return generate(str, privateKey, x509CertificateArr, str2, null);
    }

    public OCSPReq generate(String str, PrivateKey privateKey, X509Certificate[] x509CertificateArr, String str2, SecureRandom secureRandom) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
        if (str == null) {
            throw new IllegalArgumentException("no signing algorithm specified");
        }
        try {
            return generateRequest(OCSPUtil.getAlgorithmOID(str), privateKey, x509CertificateArr, str2, secureRandom);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("unknown signing algorithm specified: " + str);
        }
    }

    public Iterator getSignatureAlgNames() {
        return OCSPUtil.getAlgNames();
    }

    public void setRequestExtensions(X509Extensions x509Extensions) {
        this.requestExtensions = x509Extensions;
    }

    public void setRequestorName(X500Principal x500Principal) {
        try {
            this.requestorName = new GeneralName(4, new X509Principal(x500Principal.getEncoded()));
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot encode principal: " + e);
        }
    }

    public void setRequestorName(GeneralName generalName) {
        this.requestorName = generalName;
    }
}
