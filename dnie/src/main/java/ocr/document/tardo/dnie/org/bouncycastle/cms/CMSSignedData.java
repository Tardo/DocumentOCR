package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertStore;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.NoSuchStoreException;
import org.bouncycastle.x509.X509Store;

public class CMSSignedData {
    private static final CMSSignedHelper HELPER = CMSSignedHelper.INSTANCE;
    X509Store attributeStore;
    X509Store certificateStore;
    ContentInfo contentInfo;
    X509Store crlStore;
    private Map hashes;
    CMSTypedData signedContent;
    SignedData signedData;
    SignerInformationStore signerInfoStore;

    public CMSSignedData(InputStream inputStream) throws CMSException {
        this(CMSUtils.readContentInfo(inputStream));
    }

    public CMSSignedData(Map map, ContentInfo contentInfo) throws CMSException {
        this.hashes = map;
        this.contentInfo = contentInfo;
        this.signedData = getSignedData();
    }

    public CMSSignedData(Map map, byte[] bArr) throws CMSException {
        this(map, CMSUtils.readContentInfo(bArr));
    }

    public CMSSignedData(ContentInfo contentInfo) throws CMSException {
        this.contentInfo = contentInfo;
        this.signedData = getSignedData();
        if (this.signedData.getEncapContentInfo().getContent() != null) {
            this.signedContent = new CMSProcessableByteArray(this.signedData.getEncapContentInfo().getContentType(), ((ASN1OctetString) this.signedData.getEncapContentInfo().getContent()).getOctets());
        } else {
            this.signedContent = null;
        }
    }

    public CMSSignedData(CMSProcessable cMSProcessable, InputStream inputStream) throws CMSException {
        this(cMSProcessable, CMSUtils.readContentInfo(new ASN1InputStream(inputStream)));
    }

    public CMSSignedData(final CMSProcessable cMSProcessable, ContentInfo contentInfo) throws CMSException {
        if (cMSProcessable instanceof CMSTypedData) {
            this.signedContent = (CMSTypedData) cMSProcessable;
        } else {
            this.signedContent = new CMSTypedData() {
                public Object getContent() {
                    return cMSProcessable.getContent();
                }

                public ASN1ObjectIdentifier getContentType() {
                    return CMSSignedData.this.signedData.getEncapContentInfo().getContentType();
                }

                public void write(OutputStream outputStream) throws IOException, CMSException {
                    cMSProcessable.write(outputStream);
                }
            };
        }
        this.contentInfo = contentInfo;
        this.signedData = getSignedData();
    }

    public CMSSignedData(CMSProcessable cMSProcessable, byte[] bArr) throws CMSException {
        this(cMSProcessable, CMSUtils.readContentInfo(bArr));
    }

    private CMSSignedData(CMSSignedData cMSSignedData) {
        this.signedData = cMSSignedData.signedData;
        this.contentInfo = cMSSignedData.contentInfo;
        this.signedContent = cMSSignedData.signedContent;
        this.signerInfoStore = cMSSignedData.signerInfoStore;
    }

    public CMSSignedData(byte[] bArr) throws CMSException {
        this(CMSUtils.readContentInfo(bArr));
    }

    private SignedData getSignedData() throws CMSException {
        try {
            return SignedData.getInstance(this.contentInfo.getContent());
        } catch (Exception e) {
            throw new CMSException("Malformed content.", e);
        } catch (Exception e2) {
            throw new CMSException("Malformed content.", e2);
        }
    }

    public static CMSSignedData replaceCertificatesAndCRLs(CMSSignedData cMSSignedData, CertStore certStore) throws CMSException {
        CMSSignedData cMSSignedData2 = new CMSSignedData(cMSSignedData);
        try {
            ASN1Set createBerSetFromList = CMSUtils.createBerSetFromList(CMSUtils.getCertificatesFromStore(certStore));
            if (createBerSetFromList.size() == 0) {
                createBerSetFromList = null;
            }
            try {
                ASN1Set createBerSetFromList2 = CMSUtils.createBerSetFromList(CMSUtils.getCRLsFromStore(certStore));
                if (createBerSetFromList2.size() == 0) {
                    createBerSetFromList2 = null;
                }
                cMSSignedData2.signedData = new SignedData(cMSSignedData.signedData.getDigestAlgorithms(), cMSSignedData.signedData.getEncapContentInfo(), createBerSetFromList, createBerSetFromList2, cMSSignedData.signedData.getSignerInfos());
                cMSSignedData2.contentInfo = new ContentInfo(cMSSignedData2.contentInfo.getContentType(), cMSSignedData2.signedData);
                return cMSSignedData2;
            } catch (Exception e) {
                throw new CMSException("error getting crls from certStore", e);
            }
        } catch (Exception e2) {
            throw new CMSException("error getting certs from certStore", e2);
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static org.bouncycastle.cms.CMSSignedData replaceCertificatesAndCRLs(org.bouncycastle.cms.CMSSignedData r7, org.bouncycastle.util.Store r8, org.bouncycastle.util.Store r9, org.bouncycastle.util.Store r10) throws org.bouncycastle.cms.CMSException {
        /*
        r0 = 0;
        r6 = new org.bouncycastle.cms.CMSSignedData;
        r6.<init>(r7);
        if (r8 != 0) goto L_0x000a;
    L_0x0008:
        if (r9 == 0) goto L_0x0066;
    L_0x000a:
        r1 = new java.util.ArrayList;
        r1.<init>();
        if (r8 == 0) goto L_0x0018;
    L_0x0011:
        r2 = org.bouncycastle.cms.CMSUtils.getCertificatesFromStore(r8);
        r1.addAll(r2);
    L_0x0018:
        if (r9 == 0) goto L_0x0021;
    L_0x001a:
        r2 = org.bouncycastle.cms.CMSUtils.getAttributeCertificatesFromStore(r9);
        r1.addAll(r2);
    L_0x0021:
        r3 = org.bouncycastle.cms.CMSUtils.createBerSetFromList(r1);
        r1 = r3.size();
        if (r1 == 0) goto L_0x0066;
    L_0x002b:
        if (r10 == 0) goto L_0x0064;
    L_0x002d:
        r1 = org.bouncycastle.cms.CMSUtils.getCRLsFromStore(r10);
        r4 = org.bouncycastle.cms.CMSUtils.createBerSetFromList(r1);
        r1 = r4.size();
        if (r1 == 0) goto L_0x0064;
    L_0x003b:
        r0 = new org.bouncycastle.asn1.cms.SignedData;
        r1 = r7.signedData;
        r1 = r1.getDigestAlgorithms();
        r2 = r7.signedData;
        r2 = r2.getEncapContentInfo();
        r5 = r7.signedData;
        r5 = r5.getSignerInfos();
        r0.<init>(r1, r2, r3, r4, r5);
        r6.signedData = r0;
        r0 = new org.bouncycastle.asn1.cms.ContentInfo;
        r1 = r6.contentInfo;
        r1 = r1.getContentType();
        r2 = r6.signedData;
        r0.<init>(r1, r2);
        r6.contentInfo = r0;
        return r6;
    L_0x0064:
        r4 = r0;
        goto L_0x003b;
    L_0x0066:
        r3 = r0;
        goto L_0x002b;
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.cms.CMSSignedData.replaceCertificatesAndCRLs(org.bouncycastle.cms.CMSSignedData, org.bouncycastle.util.Store, org.bouncycastle.util.Store, org.bouncycastle.util.Store):org.bouncycastle.cms.CMSSignedData");
    }

    public static CMSSignedData replaceSigners(CMSSignedData cMSSignedData, SignerInformationStore signerInformationStore) {
        CMSSignedData cMSSignedData2 = new CMSSignedData(cMSSignedData);
        cMSSignedData2.signerInfoStore = signerInformationStore;
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
        for (SignerInformation signerInformation : signerInformationStore.getSigners()) {
            aSN1EncodableVector.add(CMSSignedHelper.INSTANCE.fixAlgID(signerInformation.getDigestAlgorithmID()));
            aSN1EncodableVector2.add(signerInformation.toASN1Structure());
        }
        ASN1Encodable dERSet = new DERSet(aSN1EncodableVector);
        ASN1Encodable dERSet2 = new DERSet(aSN1EncodableVector2);
        ASN1Sequence aSN1Sequence = (ASN1Sequence) cMSSignedData.signedData.toASN1Primitive();
        aSN1EncodableVector2 = new ASN1EncodableVector();
        aSN1EncodableVector2.add(aSN1Sequence.getObjectAt(0));
        aSN1EncodableVector2.add(dERSet);
        for (int i = 2; i != aSN1Sequence.size() - 1; i++) {
            aSN1EncodableVector2.add(aSN1Sequence.getObjectAt(i));
        }
        aSN1EncodableVector2.add(dERSet2);
        cMSSignedData2.signedData = SignedData.getInstance(new BERSequence(aSN1EncodableVector2));
        cMSSignedData2.contentInfo = new ContentInfo(cMSSignedData2.contentInfo.getContentType(), cMSSignedData2.signedData);
        return cMSSignedData2;
    }

    public Store getAttributeCertificates() {
        return HELPER.getAttributeCertificates(this.signedData.getCertificates());
    }

    public X509Store getAttributeCertificates(String str, String str2) throws NoSuchStoreException, NoSuchProviderException, CMSException {
        return getAttributeCertificates(str, CMSUtils.getProvider(str2));
    }

    public X509Store getAttributeCertificates(String str, Provider provider) throws NoSuchStoreException, CMSException {
        if (this.attributeStore == null) {
            this.attributeStore = HELPER.createAttributeStore(str, provider, getAttributeCertificates());
        }
        return this.attributeStore;
    }

    public Store getCRLs() {
        return HELPER.getCRLs(this.signedData.getCRLs());
    }

    public X509Store getCRLs(String str, String str2) throws NoSuchStoreException, NoSuchProviderException, CMSException {
        return getCRLs(str, CMSUtils.getProvider(str2));
    }

    public X509Store getCRLs(String str, Provider provider) throws NoSuchStoreException, CMSException {
        if (this.crlStore == null) {
            this.crlStore = HELPER.createCRLsStore(str, provider, getCRLs());
        }
        return this.crlStore;
    }

    public Store getCertificates() {
        return HELPER.getCertificates(this.signedData.getCertificates());
    }

    public X509Store getCertificates(String str, String str2) throws NoSuchStoreException, NoSuchProviderException, CMSException {
        return getCertificates(str, CMSUtils.getProvider(str2));
    }

    public X509Store getCertificates(String str, Provider provider) throws NoSuchStoreException, CMSException {
        if (this.certificateStore == null) {
            this.certificateStore = HELPER.createCertificateStore(str, provider, getCertificates());
        }
        return this.certificateStore;
    }

    public CertStore getCertificatesAndCRLs(String str, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return getCertificatesAndCRLs(str, CMSUtils.getProvider(str2));
    }

    public CertStore getCertificatesAndCRLs(String str, Provider provider) throws NoSuchAlgorithmException, CMSException {
        try {
            JcaCertStoreBuilder type = new JcaCertStoreBuilder().setType(str);
            if (provider != null) {
                type.setProvider(provider);
            }
            type.addCertificates(getCertificates());
            type.addCRLs(getCRLs());
            return type.build();
        } catch (NoSuchAlgorithmException e) {
            throw e;
        } catch (Exception e2) {
            throw new CMSException("exception creating CertStore: " + e2.getMessage(), e2);
        }
    }

    public ContentInfo getContentInfo() {
        return this.contentInfo;
    }

    public byte[] getEncoded() throws IOException {
        return this.contentInfo.getEncoded();
    }

    public Store getOtherRevocationInfo(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return HELPER.getOtherRevocationInfo(aSN1ObjectIdentifier, this.signedData.getCRLs());
    }

    public CMSTypedData getSignedContent() {
        return this.signedContent;
    }

    public String getSignedContentTypeOID() {
        return this.signedData.getEncapContentInfo().getContentType().getId();
    }

    public SignerInformationStore getSignerInfos() {
        if (this.signerInfoStore == null) {
            ASN1Set signerInfos = this.signedData.getSignerInfos();
            Collection arrayList = new ArrayList();
            DefaultSignatureAlgorithmIdentifierFinder defaultSignatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
            for (int i = 0; i != signerInfos.size(); i++) {
                SignerInfo instance = SignerInfo.getInstance(signerInfos.getObjectAt(i));
                ASN1ObjectIdentifier contentType = this.signedData.getEncapContentInfo().getContentType();
                if (this.hashes == null) {
                    arrayList.add(new SignerInformation(instance, contentType, this.signedContent, null));
                } else {
                    arrayList.add(new SignerInformation(instance, contentType, null, this.hashes.keySet().iterator().next() instanceof String ? (byte[]) this.hashes.get(instance.getDigestAlgorithm().getAlgorithm().getId()) : (byte[]) this.hashes.get(instance.getDigestAlgorithm().getAlgorithm())));
                }
            }
            this.signerInfoStore = new SignerInformationStore(arrayList);
        }
        return this.signerInfoStore;
    }

    public int getVersion() {
        return this.signedData.getVersion().getValue().intValue();
    }

    public ContentInfo toASN1Structure() {
        return this.contentInfo;
    }

    public boolean verifySignatures(SignerInformationVerifierProvider signerInformationVerifierProvider) throws CMSException {
        return verifySignatures(signerInformationVerifierProvider, false);
    }

    public boolean verifySignatures(SignerInformationVerifierProvider signerInformationVerifierProvider, boolean z) throws CMSException {
        for (SignerInformation signerInformation : getSignerInfos().getSigners()) {
            try {
                if (!signerInformation.verify(signerInformationVerifierProvider.get(signerInformation.getSID()))) {
                    return false;
                }
                if (!z) {
                    for (SignerInformation verify : signerInformation.getCounterSignatures().getSigners()) {
                        if (!verify.verify(signerInformationVerifierProvider.get(signerInformation.getSID()))) {
                            return false;
                        }
                    }
                    continue;
                }
            } catch (Exception e) {
                throw new CMSException("failure in verifier provider: " + e.getMessage(), e);
            }
        }
        return true;
    }
}
