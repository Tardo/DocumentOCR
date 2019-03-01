package org.bouncycastle.ocsp;

import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;

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

        public ResponseObject(CertificateID certificateID, CertificateStatus certificateStatus, Date date, Date date2, X509Extensions x509Extensions) {
            this.certId = certificateID;
            if (certificateStatus == null) {
                this.certStatus = new CertStatus();
            } else if (certificateStatus instanceof UnknownStatus) {
                this.certStatus = new CertStatus(2, DERNull.INSTANCE);
            } else {
                RevokedStatus revokedStatus = (RevokedStatus) certificateStatus;
                if (revokedStatus.hasRevocationReason()) {
                    this.certStatus = new CertStatus(new RevokedInfo(new ASN1GeneralizedTime(revokedStatus.getRevocationTime()), CRLReason.lookup(revokedStatus.getRevocationReason())));
                } else {
                    this.certStatus = new CertStatus(new RevokedInfo(new ASN1GeneralizedTime(revokedStatus.getRevocationTime()), null));
                }
            }
            this.thisUpdate = new DERGeneralizedTime(date);
            if (date2 != null) {
                this.nextUpdate = new DERGeneralizedTime(date2);
            } else {
                this.nextUpdate = null;
            }
            this.extensions = x509Extensions;
        }

        public SingleResponse toResponse() throws Exception {
            return new SingleResponse(this.certId.toASN1Object(), this.certStatus, this.thisUpdate, this.nextUpdate, this.extensions);
        }
    }

    public BasicOCSPRespGenerator(PublicKey publicKey) throws OCSPException {
        this.responderID = new RespID(publicKey);
    }

    public BasicOCSPRespGenerator(RespID respID) {
        this.responderID = respID;
    }

    private BasicOCSPResp generateResponse(String str, PrivateKey privateKey, X509Certificate[] x509CertificateArr, Date date, String str2, SecureRandom secureRandom) throws OCSPException, NoSuchProviderException {
        try {
            DERObjectIdentifier algorithmOID = OCSPUtil.getAlgorithmOID(str);
            ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
            for (ResponseObject toResponse : this.list) {
                try {
                    aSN1EncodableVector.add(toResponse.toResponse());
                } catch (Exception e) {
                    throw new OCSPException("exception creating Request", e);
                }
            }
            ResponseData responseData = new ResponseData(this.responderID.toASN1Object(), new DERGeneralizedTime(date), new DERSequence(aSN1EncodableVector), this.responseExtensions);
            try {
                Signature createSignatureInstance = OCSPUtil.createSignatureInstance(str, str2);
                if (secureRandom != null) {
                    createSignatureInstance.initSign(privateKey, secureRandom);
                } else {
                    createSignatureInstance.initSign(privateKey);
                }
                try {
                    createSignatureInstance.update(responseData.getEncoded("DER"));
                    DERBitString dERBitString = new DERBitString(createSignatureInstance.sign());
                    AlgorithmIdentifier sigAlgID = OCSPUtil.getSigAlgID(algorithmOID);
                    ASN1Sequence aSN1Sequence = null;
                    if (x509CertificateArr != null && x509CertificateArr.length > 0) {
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
                        aSN1Sequence = new DERSequence(aSN1EncodableVector2);
                    }
                    return new BasicOCSPResp(new BasicOCSPResponse(responseData, sigAlgID, dERBitString, aSN1Sequence));
                } catch (Exception e222) {
                    throw new OCSPException("exception processing TBSRequest: " + e222, e222);
                }
            } catch (NoSuchProviderException e3) {
                throw e3;
            } catch (Exception e2222) {
                throw new OCSPException("exception creating signature: " + e2222, e2222);
            }
        } catch (Exception e4) {
            throw new IllegalArgumentException("unknown signing algorithm specified");
        }
    }

    public void addResponse(CertificateID certificateID, CertificateStatus certificateStatus) {
        this.list.add(new ResponseObject(certificateID, certificateStatus, new Date(), null, null));
    }

    public void addResponse(CertificateID certificateID, CertificateStatus certificateStatus, Date date, Date date2, X509Extensions x509Extensions) {
        this.list.add(new ResponseObject(certificateID, certificateStatus, date, date2, x509Extensions));
    }

    public void addResponse(CertificateID certificateID, CertificateStatus certificateStatus, Date date, X509Extensions x509Extensions) {
        this.list.add(new ResponseObject(certificateID, certificateStatus, new Date(), date, x509Extensions));
    }

    public void addResponse(CertificateID certificateID, CertificateStatus certificateStatus, X509Extensions x509Extensions) {
        this.list.add(new ResponseObject(certificateID, certificateStatus, new Date(), null, x509Extensions));
    }

    public BasicOCSPResp generate(String str, PrivateKey privateKey, X509Certificate[] x509CertificateArr, Date date, String str2) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
        return generate(str, privateKey, x509CertificateArr, date, str2, null);
    }

    public BasicOCSPResp generate(String str, PrivateKey privateKey, X509Certificate[] x509CertificateArr, Date date, String str2, SecureRandom secureRandom) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
        if (str != null) {
            return generateResponse(str, privateKey, x509CertificateArr, date, str2, secureRandom);
        }
        throw new IllegalArgumentException("no signing algorithm specified");
    }

    public Iterator getSignatureAlgNames() {
        return OCSPUtil.getAlgNames();
    }

    public void setResponseExtensions(X509Extensions x509Extensions) {
        this.responseExtensions = x509Extensions;
    }
}
