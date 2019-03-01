package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.RawContentVerifier;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.TeeOutputStream;

public class SignerInformation {
    private CMSProcessable content;
    private ASN1ObjectIdentifier contentType;
    private AlgorithmIdentifier digestAlgorithm;
    private AlgorithmIdentifier encryptionAlgorithm;
    private SignerInfo info;
    private boolean isCounterSignature;
    private byte[] resultDigest;
    private SignerId sid;
    private byte[] signature;
    private final ASN1Set signedAttributeSet;
    private AttributeTable signedAttributeValues;
    private final ASN1Set unsignedAttributeSet;
    private AttributeTable unsignedAttributeValues;

    SignerInformation(SignerInfo signerInfo, ASN1ObjectIdentifier aSN1ObjectIdentifier, CMSProcessable cMSProcessable, byte[] bArr) {
        this.info = signerInfo;
        this.contentType = aSN1ObjectIdentifier;
        this.isCounterSignature = aSN1ObjectIdentifier == null;
        SignerIdentifier sid = signerInfo.getSID();
        if (sid.isTagged()) {
            this.sid = new SignerId(ASN1OctetString.getInstance(sid.getId()).getOctets());
        } else {
            IssuerAndSerialNumber instance = IssuerAndSerialNumber.getInstance(sid.getId());
            this.sid = new SignerId(instance.getName(), instance.getSerialNumber().getValue());
        }
        this.digestAlgorithm = signerInfo.getDigestAlgorithm();
        this.signedAttributeSet = signerInfo.getAuthenticatedAttributes();
        this.unsignedAttributeSet = signerInfo.getUnauthenticatedAttributes();
        this.encryptionAlgorithm = signerInfo.getDigestEncryptionAlgorithm();
        this.signature = signerInfo.getEncryptedDigest().getOctets();
        this.content = cMSProcessable;
        this.resultDigest = bArr;
    }

    public static SignerInformation addCounterSigners(SignerInformation signerInformation, SignerInformationStore signerInformationStore) {
        SignerInfo signerInfo = signerInformation.info;
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        ASN1EncodableVector toASN1EncodableVector = unsignedAttributes != null ? unsignedAttributes.toASN1EncodableVector() : new ASN1EncodableVector();
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        for (SignerInformation toASN1Structure : signerInformationStore.getSigners()) {
            aSN1EncodableVector.add(toASN1Structure.toASN1Structure());
        }
        toASN1EncodableVector.add(new Attribute(CMSAttributes.counterSignature, new DERSet(aSN1EncodableVector)));
        return new SignerInformation(new SignerInfo(signerInfo.getSID(), signerInfo.getDigestAlgorithm(), signerInfo.getAuthenticatedAttributes(), signerInfo.getDigestEncryptionAlgorithm(), signerInfo.getEncryptedDigest(), new DERSet(toASN1EncodableVector)), signerInformation.contentType, signerInformation.content, null);
    }

    private boolean doVerify(PublicKey publicKey, Provider provider) throws CMSException, NoSuchAlgorithmException {
        SignerInformationVerifier build;
        if (provider != null) {
            try {
                build = !provider.getName().equalsIgnoreCase(BouncyCastleProvider.PROVIDER_NAME) ? new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build()).setProvider(provider).build(publicKey) : new JcaSimpleSignerInfoVerifierBuilder().setProvider(provider).build(publicKey);
            } catch (Exception e) {
                throw new CMSException("unable to create verifier: " + e.getMessage(), e);
            }
        }
        build = new JcaSimpleSignerInfoVerifierBuilder().build(publicKey);
        return doVerify(build);
    }

    private boolean doVerify(SignerInformationVerifier signerInformationVerifier) throws CMSException {
        String encryptionAlgName = CMSSignedHelper.INSTANCE.getEncryptionAlgName(getEncryptionAlgOID());
        try {
            ContentVerifier contentVerifier = signerInformationVerifier.getContentVerifier(this.encryptionAlgorithm, this.info.getDigestAlgorithm());
            try {
                OutputStream outputStream = contentVerifier.getOutputStream();
                if (this.resultDigest == null) {
                    DigestCalculator digestCalculator = signerInformationVerifier.getDigestCalculator(getDigestAlgorithmID());
                    if (this.content != null) {
                        OutputStream outputStream2 = digestCalculator.getOutputStream();
                        if (this.signedAttributeSet != null) {
                            this.content.write(outputStream2);
                            outputStream.write(getEncodedSignedAttributes());
                        } else if (contentVerifier instanceof RawContentVerifier) {
                            this.content.write(outputStream2);
                        } else {
                            OutputStream teeOutputStream = new TeeOutputStream(outputStream2, outputStream);
                            this.content.write(teeOutputStream);
                            teeOutputStream.close();
                        }
                        outputStream2.close();
                    } else if (this.signedAttributeSet != null) {
                        outputStream.write(getEncodedSignedAttributes());
                    } else {
                        throw new CMSException("data not encapsulated in signature - use detached constructor.");
                    }
                    this.resultDigest = digestCalculator.getDigest();
                } else if (this.signedAttributeSet != null) {
                    outputStream.write(getEncodedSignedAttributes());
                } else if (this.content != null) {
                    this.content.write(outputStream);
                }
                outputStream.close();
                ASN1Primitive singleValuedSignedAttribute = getSingleValuedSignedAttribute(CMSAttributes.contentType, "content-type");
                if (singleValuedSignedAttribute == null) {
                    if (!(this.isCounterSignature || this.signedAttributeSet == null)) {
                        throw new CMSException("The content-type attribute type MUST be present whenever signed attributes are present in signed-data");
                    }
                } else if (this.isCounterSignature) {
                    throw new CMSException("[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute");
                } else if (!(singleValuedSignedAttribute instanceof ASN1ObjectIdentifier)) {
                    throw new CMSException("content-type attribute value not of ASN.1 type 'OBJECT IDENTIFIER'");
                } else if (!((ASN1ObjectIdentifier) singleValuedSignedAttribute).equals(this.contentType)) {
                    throw new CMSException("content-type attribute value does not match eContentType");
                }
                singleValuedSignedAttribute = getSingleValuedSignedAttribute(CMSAttributes.messageDigest, "message-digest");
                if (singleValuedSignedAttribute == null) {
                    if (this.signedAttributeSet != null) {
                        throw new CMSException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
                    }
                } else if (singleValuedSignedAttribute instanceof ASN1OctetString) {
                    if (!Arrays.constantTimeAreEqual(this.resultDigest, ((ASN1OctetString) singleValuedSignedAttribute).getOctets())) {
                        throw new CMSSignerDigestMismatchException("message-digest attribute value does not match calculated value");
                    }
                } else {
                    throw new CMSException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");
                }
                AttributeTable signedAttributes = getSignedAttributes();
                if (signedAttributes == null || signedAttributes.getAll(CMSAttributes.counterSignature).size() <= 0) {
                    signedAttributes = getUnsignedAttributes();
                    if (signedAttributes != null) {
                        ASN1EncodableVector all = signedAttributes.getAll(CMSAttributes.counterSignature);
                        for (int i = 0; i < all.size(); i++) {
                            if (((Attribute) all.get(i)).getAttrValues().size() < 1) {
                                throw new CMSException("A countersignature attribute MUST contain at least one AttributeValue");
                            }
                        }
                    }
                    try {
                        if (this.signedAttributeSet != null || this.resultDigest == null || !(contentVerifier instanceof RawContentVerifier)) {
                            return contentVerifier.verify(getSignature());
                        }
                        RawContentVerifier rawContentVerifier = (RawContentVerifier) contentVerifier;
                        return encryptionAlgName.equals("RSA") ? rawContentVerifier.verify(new DigestInfo(new AlgorithmIdentifier(this.digestAlgorithm.getAlgorithm(), DERNull.INSTANCE), this.resultDigest).getEncoded("DER"), getSignature()) : rawContentVerifier.verify(this.resultDigest, getSignature());
                    } catch (Exception e) {
                        throw new CMSException("can't process mime object to create signature.", e);
                    }
                }
                throw new CMSException("A countersignature attribute MUST NOT be a signed attribute");
            } catch (Exception e2) {
                throw new CMSException("can't process mime object to create signature.", e2);
            } catch (Exception e22) {
                throw new CMSException("can't create digest calculator: " + e22.getMessage(), e22);
            }
        } catch (Exception e222) {
            throw new CMSException("can't create content verifier: " + e222.getMessage(), e222);
        }
    }

    private byte[] encodeObj(ASN1Encodable aSN1Encodable) throws IOException {
        return aSN1Encodable != null ? aSN1Encodable.toASN1Primitive().getEncoded() : null;
    }

    private Time getSigningTime() throws CMSException {
        ASN1Primitive singleValuedSignedAttribute = getSingleValuedSignedAttribute(CMSAttributes.signingTime, "signing-time");
        if (singleValuedSignedAttribute == null) {
            return null;
        }
        try {
            return Time.getInstance(singleValuedSignedAttribute);
        } catch (IllegalArgumentException e) {
            throw new CMSException("signing-time attribute value not a valid 'Time' structure");
        }
    }

    private ASN1Primitive getSingleValuedSignedAttribute(ASN1ObjectIdentifier aSN1ObjectIdentifier, String str) throws CMSException {
        AttributeTable unsignedAttributes = getUnsignedAttributes();
        if (unsignedAttributes == null || unsignedAttributes.getAll(aSN1ObjectIdentifier).size() <= 0) {
            unsignedAttributes = getSignedAttributes();
            if (unsignedAttributes == null) {
                return null;
            }
            ASN1EncodableVector all = unsignedAttributes.getAll(aSN1ObjectIdentifier);
            switch (all.size()) {
                case 0:
                    return null;
                case 1:
                    ASN1Set attrValues = ((Attribute) all.get(0)).getAttrValues();
                    if (attrValues.size() == 1) {
                        return attrValues.getObjectAt(0).toASN1Primitive();
                    }
                    throw new CMSException("A " + str + " attribute MUST have a single attribute value");
                default:
                    throw new CMSException("The SignedAttributes in a signerInfo MUST NOT include multiple instances of the " + str + " attribute");
            }
        }
        throw new CMSException("The " + str + " attribute MUST NOT be an unsigned attribute");
    }

    public static SignerInformation replaceUnsignedAttributes(SignerInformation signerInformation, AttributeTable attributeTable) {
        SignerInfo signerInfo = signerInformation.info;
        return new SignerInformation(new SignerInfo(signerInfo.getSID(), signerInfo.getDigestAlgorithm(), signerInfo.getAuthenticatedAttributes(), signerInfo.getDigestEncryptionAlgorithm(), signerInfo.getEncryptedDigest(), attributeTable != null ? new DERSet(attributeTable.toASN1EncodableVector()) : null), signerInformation.contentType, signerInformation.content, null);
    }

    public byte[] getContentDigest() {
        if (this.resultDigest != null) {
            return (byte[]) this.resultDigest.clone();
        }
        throw new IllegalStateException("method can only be called after verify.");
    }

    public ASN1ObjectIdentifier getContentType() {
        return this.contentType;
    }

    public SignerInformationStore getCounterSignatures() {
        AttributeTable unsignedAttributes = getUnsignedAttributes();
        if (unsignedAttributes == null) {
            return new SignerInformationStore(new ArrayList(0));
        }
        Collection arrayList = new ArrayList();
        ASN1EncodableVector all = unsignedAttributes.getAll(CMSAttributes.counterSignature);
        for (int i = 0; i < all.size(); i++) {
            Enumeration objects;
            ASN1Set attrValues = ((Attribute) all.get(i)).getAttrValues();
            if (attrValues.size() < 1) {
                objects = attrValues.getObjects();
            } else {
                objects = attrValues.getObjects();
            }
            while (objects.hasMoreElements()) {
                arrayList.add(new SignerInformation(SignerInfo.getInstance(objects.nextElement()), null, new CMSProcessableByteArray(getSignature()), null));
            }
        }
        return new SignerInformationStore(arrayList);
    }

    public String getDigestAlgOID() {
        return this.digestAlgorithm.getAlgorithm().getId();
    }

    public byte[] getDigestAlgParams() {
        try {
            return encodeObj(this.digestAlgorithm.getParameters());
        } catch (Exception e) {
            throw new RuntimeException("exception getting digest parameters " + e);
        }
    }

    public AlgorithmIdentifier getDigestAlgorithmID() {
        return this.digestAlgorithm;
    }

    public byte[] getEncodedSignedAttributes() throws IOException {
        return this.signedAttributeSet != null ? this.signedAttributeSet.getEncoded() : null;
    }

    public String getEncryptionAlgOID() {
        return this.encryptionAlgorithm.getAlgorithm().getId();
    }

    public byte[] getEncryptionAlgParams() {
        try {
            return encodeObj(this.encryptionAlgorithm.getParameters());
        } catch (Exception e) {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }

    public SignerId getSID() {
        return this.sid;
    }

    public byte[] getSignature() {
        return (byte[]) this.signature.clone();
    }

    public AttributeTable getSignedAttributes() {
        if (this.signedAttributeSet != null && this.signedAttributeValues == null) {
            this.signedAttributeValues = new AttributeTable(this.signedAttributeSet);
        }
        return this.signedAttributeValues;
    }

    public AttributeTable getUnsignedAttributes() {
        if (this.unsignedAttributeSet != null && this.unsignedAttributeValues == null) {
            this.unsignedAttributeValues = new AttributeTable(this.unsignedAttributeSet);
        }
        return this.unsignedAttributeValues;
    }

    public int getVersion() {
        return this.info.getVersion().getValue().intValue();
    }

    public boolean isCounterSignature() {
        return this.isCounterSignature;
    }

    public SignerInfo toASN1Structure() {
        return this.info;
    }

    public SignerInfo toSignerInfo() {
        return this.info;
    }

    public boolean verify(PublicKey publicKey, String str) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return verify(publicKey, CMSUtils.getProvider(str));
    }

    public boolean verify(PublicKey publicKey, Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        getSigningTime();
        return doVerify(publicKey, provider);
    }

    public boolean verify(X509Certificate x509Certificate, String str) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateExpiredException, CertificateNotYetValidException, CMSException {
        return verify(x509Certificate, CMSUtils.getProvider(str));
    }

    public boolean verify(X509Certificate x509Certificate, Provider provider) throws NoSuchAlgorithmException, CertificateExpiredException, CertificateNotYetValidException, CMSException {
        Time signingTime = getSigningTime();
        if (signingTime != null) {
            x509Certificate.checkValidity(signingTime.getDate());
        }
        return doVerify(x509Certificate.getPublicKey(), provider);
    }

    public boolean verify(SignerInformationVerifier signerInformationVerifier) throws CMSException {
        Time signingTime = getSigningTime();
        if (!signerInformationVerifier.hasAssociatedCertificate() || signingTime == null || signerInformationVerifier.getAssociatedCertificate().isValidOn(signingTime.getDate())) {
            return doVerify(signerInformationVerifier);
        }
        throw new CMSVerifierCertificateNotValidException("verifier not valid at signingTime");
    }
}
