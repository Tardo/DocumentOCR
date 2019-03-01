package org.spongycastle.ocsp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.ocsp.BasicOCSPResponse;
import org.spongycastle.asn1.ocsp.CertStatus;
import org.spongycastle.asn1.ocsp.ResponseData;
import org.spongycastle.asn1.ocsp.RevokedInfo;
import org.spongycastle.asn1.ocsp.SingleResponse;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.CRLReason;
import org.spongycastle.asn1.x509.X509CertificateStructure;
import org.spongycastle.asn1.x509.X509Extensions;

public class BasicOCSPRespGenerator {
    private List list = new ArrayList();
    private RespID responderID;
    private X509Extensions responseExtensions = null;

    private class ResponseObject {
        CertificateID certId;
        CertStatus certStatus;
        X509Extensions extensions;
        DERGeneralizedTime nextUpdate;
        DERGeneralizedTime thisUpdate;

        public ResponseObject(CertificateID certId, CertificateStatus certStatus, Date thisUpdate, Date nextUpdate, X509Extensions extensions) {
            this.certId = certId;
            if (certStatus == null) {
                this.certStatus = new CertStatus();
            } else if (certStatus instanceof UnknownStatus) {
                this.certStatus = new CertStatus(2, new DERNull());
            } else {
                RevokedStatus rs = (RevokedStatus) certStatus;
                if (rs.hasRevocationReason()) {
                    this.certStatus = new CertStatus(new RevokedInfo(new DERGeneralizedTime(rs.getRevocationTime()), new CRLReason(rs.getRevocationReason())));
                } else {
                    this.certStatus = new CertStatus(new RevokedInfo(new DERGeneralizedTime(rs.getRevocationTime()), null));
                }
            }
            this.thisUpdate = new DERGeneralizedTime(thisUpdate);
            if (nextUpdate != null) {
                this.nextUpdate = new DERGeneralizedTime(nextUpdate);
            } else {
                this.nextUpdate = null;
            }
            this.extensions = extensions;
        }

        public SingleResponse toResponse() throws Exception {
            return new SingleResponse(this.certId.toASN1Object(), this.certStatus, this.thisUpdate, this.nextUpdate, this.extensions);
        }
    }

    public BasicOCSPRespGenerator(RespID responderID) {
        this.responderID = responderID;
    }

    public BasicOCSPRespGenerator(PublicKey key) throws OCSPException {
        this.responderID = new RespID(key);
    }

    public void addResponse(CertificateID certID, CertificateStatus certStatus) {
        this.list.add(new ResponseObject(certID, certStatus, new Date(), null, null));
    }

    public void addResponse(CertificateID certID, CertificateStatus certStatus, X509Extensions singleExtensions) {
        this.list.add(new ResponseObject(certID, certStatus, new Date(), null, singleExtensions));
    }

    public void addResponse(CertificateID certID, CertificateStatus certStatus, Date nextUpdate, X509Extensions singleExtensions) {
        this.list.add(new ResponseObject(certID, certStatus, new Date(), nextUpdate, singleExtensions));
    }

    public void addResponse(CertificateID certID, CertificateStatus certStatus, Date thisUpdate, Date nextUpdate, X509Extensions singleExtensions) {
        this.list.add(new ResponseObject(certID, certStatus, thisUpdate, nextUpdate, singleExtensions));
    }

    public void setResponseExtensions(X509Extensions responseExtensions) {
        this.responseExtensions = responseExtensions;
    }

    private BasicOCSPResp generateResponse(String signatureName, PrivateKey key, X509Certificate[] chain, Date producedAt, String provider, SecureRandom random) throws OCSPException, NoSuchProviderException {
        try {
            DERObjectIdentifier signingAlgorithm = OCSPUtil.getAlgorithmOID(signatureName);
            ASN1EncodableVector responses = new ASN1EncodableVector();
            for (ResponseObject toResponse : this.list) {
                try {
                    responses.add(toResponse.toResponse());
                } catch (Exception e) {
                    throw new OCSPException("exception creating Request", e);
                }
            }
            ResponseData tbsResp = new ResponseData(this.responderID.toASN1Object(), new DERGeneralizedTime(producedAt), new DERSequence(responses), this.responseExtensions);
            try {
                Signature sig = OCSPUtil.createSignatureInstance(signatureName, provider);
                if (random != null) {
                    sig.initSign(key, random);
                } else {
                    sig.initSign(key);
                }
                try {
                    sig.update(tbsResp.getEncoded("DER"));
                    DERBitString bitSig = new DERBitString(sig.sign());
                    AlgorithmIdentifier sigAlgId = OCSPUtil.getSigAlgID(signingAlgorithm);
                    DERSequence chainSeq = null;
                    if (chain != null && chain.length > 0) {
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
                        chainSeq = new DERSequence(v);
                    }
                    return new BasicOCSPResp(new BasicOCSPResponse(tbsResp, sigAlgId, bitSig, chainSeq));
                } catch (Exception e4) {
                    throw new OCSPException("exception processing TBSRequest: " + e4, e4);
                }
            } catch (NoSuchProviderException e5) {
                throw e5;
            } catch (GeneralSecurityException e6) {
                throw new OCSPException("exception creating signature: " + e6, e6);
            }
        } catch (Exception e7) {
            throw new IllegalArgumentException("unknown signing algorithm specified");
        }
    }

    public BasicOCSPResp generate(String signingAlgorithm, PrivateKey key, X509Certificate[] chain, Date thisUpdate, String provider) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
        return generate(signingAlgorithm, key, chain, thisUpdate, provider, null);
    }

    public BasicOCSPResp generate(String signingAlgorithm, PrivateKey key, X509Certificate[] chain, Date producedAt, String provider, SecureRandom random) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
        if (signingAlgorithm != null) {
            return generateResponse(signingAlgorithm, key, chain, producedAt, provider, random);
        }
        throw new IllegalArgumentException("no signing algorithm specified");
    }

    public Iterator getSignatureAlgNames() {
        return OCSPUtil.getAlgNames();
    }
}
