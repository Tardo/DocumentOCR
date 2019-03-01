package org.spongycastle.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1OutputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.ocsp.OCSPRequest;
import org.spongycastle.asn1.ocsp.Request;
import org.spongycastle.asn1.ocsp.Signature;
import org.spongycastle.asn1.ocsp.TBSRequest;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.X509CertificateStructure;
import org.spongycastle.asn1.x509.X509Extensions;
import org.spongycastle.jce.X509Principal;

public class OCSPReqGenerator {
    private List list = new ArrayList();
    private X509Extensions requestExtensions = null;
    private GeneralName requestorName = null;

    private class RequestObject {
        CertificateID certId;
        X509Extensions extensions;

        public RequestObject(CertificateID certId, X509Extensions extensions) {
            this.certId = certId;
            this.extensions = extensions;
        }

        public Request toRequest() throws Exception {
            return new Request(this.certId.toASN1Object(), this.extensions);
        }
    }

    public void addRequest(CertificateID certId) {
        this.list.add(new RequestObject(certId, null));
    }

    public void addRequest(CertificateID certId, X509Extensions singleRequestExtensions) {
        this.list.add(new RequestObject(certId, singleRequestExtensions));
    }

    public void setRequestorName(X500Principal requestorName) {
        try {
            this.requestorName = new GeneralName(4, new X509Principal(requestorName.getEncoded()));
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot encode principal: " + e);
        }
    }

    public void setRequestorName(GeneralName requestorName) {
        this.requestorName = requestorName;
    }

    public void setRequestExtensions(X509Extensions requestExtensions) {
        this.requestExtensions = requestExtensions;
    }

    private OCSPReq generateRequest(DERObjectIdentifier signingAlgorithm, PrivateKey key, X509Certificate[] chain, String provider, SecureRandom random) throws OCSPException, NoSuchProviderException {
        ASN1EncodableVector requests = new ASN1EncodableVector();
        for (RequestObject toRequest : this.list) {
            try {
                requests.add(toRequest.toRequest());
            } catch (Exception e) {
                throw new OCSPException("exception creating Request", e);
            }
        }
        TBSRequest tbsReq = new TBSRequest(this.requestorName, new DERSequence(requests), this.requestExtensions);
        Signature signature = null;
        if (signingAlgorithm != null) {
            if (this.requestorName == null) {
                throw new OCSPException("requestorName must be specified if request is signed.");
            }
            try {
                java.security.Signature sig = OCSPUtil.createSignatureInstance(signingAlgorithm.getId(), provider);
                if (random != null) {
                    sig.initSign(key, random);
                } else {
                    sig.initSign(key);
                }
                try {
                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                    new ASN1OutputStream(bOut).writeObject(tbsReq);
                    sig.update(bOut.toByteArray());
                    DERBitString bitSig = new DERBitString(sig.sign());
                    AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(signingAlgorithm, new DERNull());
                    if (chain == null || chain.length <= 0) {
                        signature = new Signature(sigAlgId, bitSig);
                    } else {
                        ASN1EncodableVector v = new ASN1EncodableVector();
                        int i = 0;
                        while (i != chain.length) {
                            try {
                                v.add(new X509CertificateStructure((ASN1Sequence) ASN1Object.fromByteArray(chain[i].getEncoded())));
                                i++;
                            } catch (IOException e2) {
                                throw new OCSPException("error processing certs", e2);
                            } catch (CertificateEncodingException e3) {
                                throw new OCSPException("error encoding certs", e3);
                            }
                        }
                        signature = new Signature(sigAlgId, bitSig, new DERSequence(v));
                    }
                } catch (Exception e4) {
                    throw new OCSPException("exception processing TBSRequest: " + e4, e4);
                }
            } catch (NoSuchProviderException e5) {
                throw e5;
            } catch (GeneralSecurityException e6) {
                throw new OCSPException("exception creating signature: " + e6, e6);
            }
        }
        return new OCSPReq(new OCSPRequest(tbsReq, signature));
    }

    public OCSPReq generate() throws OCSPException {
        try {
            return generateRequest(null, null, null, null, null);
        } catch (NoSuchProviderException e) {
            throw new OCSPException("no provider! - " + e, e);
        }
    }

    public OCSPReq generate(String signingAlgorithm, PrivateKey key, X509Certificate[] chain, String provider) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
        return generate(signingAlgorithm, key, chain, provider, null);
    }

    public OCSPReq generate(String signingAlgorithm, PrivateKey key, X509Certificate[] chain, String provider, SecureRandom random) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
        if (signingAlgorithm == null) {
            throw new IllegalArgumentException("no signing algorithm specified");
        }
        try {
            return generateRequest(OCSPUtil.getAlgorithmOID(signingAlgorithm), key, chain, provider, random);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("unknown signing algorithm specified: " + signingAlgorithm);
        }
    }

    public Iterator getSignatureAlgNames() {
        return OCSPUtil.getAlgNames();
    }
}
