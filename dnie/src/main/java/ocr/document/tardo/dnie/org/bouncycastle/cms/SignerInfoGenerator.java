package org.bouncycastle.cms;

import java.io.OutputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.TeeOutputStream;

public class SignerInfoGenerator {
    private byte[] calculatedDigest;
    private X509CertificateHolder certHolder;
    private final DigestAlgorithmIdentifierFinder digAlgFinder;
    private final DigestCalculator digester;
    private final CMSAttributeTableGenerator sAttrGen;
    private final CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder;
    private final ContentSigner signer;
    private final SignerIdentifier signerIdentifier;
    private final CMSAttributeTableGenerator unsAttrGen;

    SignerInfoGenerator(SignerIdentifier signerIdentifier, ContentSigner contentSigner, DigestCalculatorProvider digestCalculatorProvider, CMSSignatureEncryptionAlgorithmFinder cMSSignatureEncryptionAlgorithmFinder) throws OperatorCreationException {
        this(signerIdentifier, contentSigner, digestCalculatorProvider, cMSSignatureEncryptionAlgorithmFinder, false);
    }

    SignerInfoGenerator(SignerIdentifier signerIdentifier, ContentSigner contentSigner, DigestCalculatorProvider digestCalculatorProvider, CMSSignatureEncryptionAlgorithmFinder cMSSignatureEncryptionAlgorithmFinder, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2) throws OperatorCreationException {
        this.digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        this.calculatedDigest = null;
        this.signerIdentifier = signerIdentifier;
        this.signer = contentSigner;
        if (digestCalculatorProvider != null) {
            this.digester = digestCalculatorProvider.get(this.digAlgFinder.find(contentSigner.getAlgorithmIdentifier()));
        } else {
            this.digester = null;
        }
        this.sAttrGen = cMSAttributeTableGenerator;
        this.unsAttrGen = cMSAttributeTableGenerator2;
        this.sigEncAlgFinder = cMSSignatureEncryptionAlgorithmFinder;
    }

    SignerInfoGenerator(SignerIdentifier signerIdentifier, ContentSigner contentSigner, DigestCalculatorProvider digestCalculatorProvider, CMSSignatureEncryptionAlgorithmFinder cMSSignatureEncryptionAlgorithmFinder, boolean z) throws OperatorCreationException {
        this.digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        this.calculatedDigest = null;
        this.signerIdentifier = signerIdentifier;
        this.signer = contentSigner;
        if (digestCalculatorProvider != null) {
            this.digester = digestCalculatorProvider.get(this.digAlgFinder.find(contentSigner.getAlgorithmIdentifier()));
        } else {
            this.digester = null;
        }
        if (z) {
            this.sAttrGen = null;
            this.unsAttrGen = null;
        } else {
            this.sAttrGen = new DefaultSignedAttributeTableGenerator();
            this.unsAttrGen = null;
        }
        this.sigEncAlgFinder = cMSSignatureEncryptionAlgorithmFinder;
    }

    public SignerInfoGenerator(SignerInfoGenerator signerInfoGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2) {
        this.digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        this.calculatedDigest = null;
        this.signerIdentifier = signerInfoGenerator.signerIdentifier;
        this.signer = signerInfoGenerator.signer;
        this.digester = signerInfoGenerator.digester;
        this.sigEncAlgFinder = signerInfoGenerator.sigEncAlgFinder;
        this.sAttrGen = cMSAttributeTableGenerator;
        this.unsAttrGen = cMSAttributeTableGenerator2;
    }

    private ASN1Set getAttributeSet(AttributeTable attributeTable) {
        return attributeTable != null ? new DERSet(attributeTable.toASN1EncodableVector()) : null;
    }

    private Map getBaseParameters(ASN1ObjectIdentifier aSN1ObjectIdentifier, AlgorithmIdentifier algorithmIdentifier, byte[] bArr) {
        Map hashMap = new HashMap();
        if (aSN1ObjectIdentifier != null) {
            hashMap.put(CMSAttributeTableGenerator.CONTENT_TYPE, aSN1ObjectIdentifier);
        }
        hashMap.put(CMSAttributeTableGenerator.DIGEST_ALGORITHM_IDENTIFIER, algorithmIdentifier);
        hashMap.put(CMSAttributeTableGenerator.DIGEST, bArr.clone());
        return hashMap;
    }

    public SignerInfo generate(ASN1ObjectIdentifier aSN1ObjectIdentifier) throws CMSException {
        ASN1Set aSN1Set = null;
        try {
            AlgorithmIdentifier algorithmIdentifier;
            ASN1Set attributeSet;
            if (this.sAttrGen != null) {
                algorithmIdentifier = this.digester.getAlgorithmIdentifier();
                this.calculatedDigest = this.digester.getDigest();
                attributeSet = getAttributeSet(this.sAttrGen.getAttributes(Collections.unmodifiableMap(getBaseParameters(aSN1ObjectIdentifier, this.digester.getAlgorithmIdentifier(), this.calculatedDigest))));
                OutputStream outputStream = this.signer.getOutputStream();
                outputStream.write(attributeSet.getEncoded("DER"));
                outputStream.close();
            } else if (this.digester != null) {
                algorithmIdentifier = this.digester.getAlgorithmIdentifier();
                this.calculatedDigest = this.digester.getDigest();
                attributeSet = null;
            } else {
                algorithmIdentifier = this.digAlgFinder.find(this.signer.getAlgorithmIdentifier());
                this.calculatedDigest = null;
                attributeSet = null;
            }
            byte[] signature = this.signer.getSignature();
            if (this.unsAttrGen != null) {
                Map baseParameters = getBaseParameters(aSN1ObjectIdentifier, algorithmIdentifier, this.calculatedDigest);
                baseParameters.put(CMSAttributeTableGenerator.SIGNATURE, signature.clone());
                aSN1Set = getAttributeSet(this.unsAttrGen.getAttributes(Collections.unmodifiableMap(baseParameters)));
            }
            return new SignerInfo(this.signerIdentifier, algorithmIdentifier, attributeSet, this.sigEncAlgFinder.findEncryptionAlgorithm(this.signer.getAlgorithmIdentifier()), new DEROctetString(signature), aSN1Set);
        } catch (Exception e) {
            throw new CMSException("encoding error.", e);
        }
    }

    public X509CertificateHolder getAssociatedCertificate() {
        return this.certHolder;
    }

    public byte[] getCalculatedDigest() {
        return this.calculatedDigest != null ? (byte[]) this.calculatedDigest.clone() : null;
    }

    public OutputStream getCalculatingOutputStream() {
        return this.digester != null ? this.sAttrGen == null ? new TeeOutputStream(this.digester.getOutputStream(), this.signer.getOutputStream()) : this.digester.getOutputStream() : this.signer.getOutputStream();
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return this.digester != null ? this.digester.getAlgorithmIdentifier() : this.digAlgFinder.find(this.signer.getAlgorithmIdentifier());
    }

    public ASN1Integer getGeneratedVersion() {
        return new ASN1Integer(this.signerIdentifier.isTagged() ? 3 : 1);
    }

    public SignerIdentifier getSID() {
        return this.signerIdentifier;
    }

    public CMSAttributeTableGenerator getSignedAttributeTableGenerator() {
        return this.sAttrGen;
    }

    public CMSAttributeTableGenerator getUnsignedAttributeTableGenerator() {
        return this.unsAttrGen;
    }

    public boolean hasAssociatedCertificate() {
        return this.certHolder != null;
    }

    void setAssociatedCertificate(X509CertificateHolder x509CertificateHolder) {
        this.certHolder = x509CertificateHolder;
    }
}
