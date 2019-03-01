package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CMSSignedDataGenerator extends CMSSignedGenerator {
    private List signerInfs = new ArrayList();

    private class SignerInf {
        final AttributeTable baseSignedTable;
        final String digestOID;
        final String encOID;
        final PrivateKey key;
        final CMSAttributeTableGenerator sAttr;
        final Object signerIdentifier;
        final CMSAttributeTableGenerator unsAttr;

        SignerInf(PrivateKey privateKey, Object obj, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, AttributeTable attributeTable) {
            this.key = privateKey;
            this.signerIdentifier = obj;
            this.digestOID = str;
            this.encOID = str2;
            this.sAttr = cMSAttributeTableGenerator;
            this.unsAttr = cMSAttributeTableGenerator2;
            this.baseSignedTable = attributeTable;
        }

        SignerInfoGenerator toSignerInfoGenerator(SecureRandom secureRandom, Provider provider, boolean z) throws IOException, CertificateEncodingException, CMSException, OperatorCreationException, NoSuchAlgorithmException {
            String str = CMSSignedHelper.INSTANCE.getDigestAlgName(this.digestOID) + "with" + CMSSignedHelper.INSTANCE.getEncryptionAlgName(this.encOID);
            JcaSignerInfoGeneratorBuilder jcaSignerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new BcDigestCalculatorProvider());
            if (z) {
                jcaSignerInfoGeneratorBuilder.setSignedAttributeGenerator(this.sAttr);
            }
            jcaSignerInfoGeneratorBuilder.setDirectSignature(!z);
            jcaSignerInfoGeneratorBuilder.setUnsignedAttributeGenerator(this.unsAttr);
            try {
                JcaContentSignerBuilder secureRandom2 = new JcaContentSignerBuilder(str).setSecureRandom(secureRandom);
                if (provider != null) {
                    secureRandom2.setProvider(provider);
                }
                ContentSigner build = secureRandom2.build(this.key);
                return this.signerIdentifier instanceof X509Certificate ? jcaSignerInfoGeneratorBuilder.build(build, (X509Certificate) this.signerIdentifier) : jcaSignerInfoGeneratorBuilder.build(build, (byte[]) this.signerIdentifier);
            } catch (IllegalArgumentException e) {
                throw new NoSuchAlgorithmException(e.getMessage());
            }
        }
    }

    public CMSSignedDataGenerator(SecureRandom secureRandom) {
        super(secureRandom);
    }

    private void doAddSigner(PrivateKey privateKey, Object obj, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, AttributeTable attributeTable) throws IllegalArgumentException {
        this.signerInfs.add(new SignerInf(privateKey, obj, str2, str, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, attributeTable));
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str) throws IllegalArgumentException {
        addSigner(privateKey, x509Certificate, getEncOID(privateKey, str), str);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2) throws IllegalArgumentException {
        doAddSigner(privateKey, x509Certificate, str, str2, new DefaultSignedAttributeTableGenerator(), null, null);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2, AttributeTable attributeTable, AttributeTable attributeTable2) throws IllegalArgumentException {
        doAddSigner(privateKey, x509Certificate, str, str2, new DefaultSignedAttributeTableGenerator(attributeTable), new SimpleAttributeTableGenerator(attributeTable2), attributeTable);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2) throws IllegalArgumentException {
        doAddSigner(privateKey, x509Certificate, str, str2, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, null);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, AttributeTable attributeTable, AttributeTable attributeTable2) throws IllegalArgumentException {
        addSigner(privateKey, x509Certificate, getEncOID(privateKey, str), str, attributeTable, attributeTable2);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2) throws IllegalArgumentException {
        addSigner(privateKey, x509Certificate, getEncOID(privateKey, str), str, cMSAttributeTableGenerator, cMSAttributeTableGenerator2);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str) throws IllegalArgumentException {
        addSigner(privateKey, bArr, getEncOID(privateKey, str), str);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, String str2) throws IllegalArgumentException {
        doAddSigner(privateKey, bArr, str, str2, new DefaultSignedAttributeTableGenerator(), null, null);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, String str2, AttributeTable attributeTable, AttributeTable attributeTable2) throws IllegalArgumentException {
        doAddSigner(privateKey, bArr, str, str2, new DefaultSignedAttributeTableGenerator(attributeTable), new SimpleAttributeTableGenerator(attributeTable2), attributeTable);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2) throws IllegalArgumentException {
        doAddSigner(privateKey, bArr, str, str2, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, null);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, AttributeTable attributeTable, AttributeTable attributeTable2) throws IllegalArgumentException {
        addSigner(privateKey, bArr, getEncOID(privateKey, str), str, attributeTable, attributeTable2);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2) throws IllegalArgumentException {
        addSigner(privateKey, bArr, getEncOID(privateKey, str), str, cMSAttributeTableGenerator, cMSAttributeTableGenerator2);
    }

    public CMSSignedData generate(String str, CMSProcessable cMSProcessable, boolean z, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return generate(str, cMSProcessable, z, CMSUtils.getProvider(str2), true);
    }

    public CMSSignedData generate(String str, CMSProcessable cMSProcessable, boolean z, String str2, boolean z2) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return generate(str, cMSProcessable, z, CMSUtils.getProvider(str2), z2);
    }

    public CMSSignedData generate(String str, CMSProcessable cMSProcessable, boolean z, Provider provider) throws NoSuchAlgorithmException, CMSException {
        return generate(str, cMSProcessable, z, provider, true);
    }

    public CMSSignedData generate(String str, final CMSProcessable cMSProcessable, boolean z, Provider provider, boolean z2) throws NoSuchAlgorithmException, CMSException {
        final ASN1ObjectIdentifier aSN1ObjectIdentifier = (str == null ? 1 : null) != null ? null : new ASN1ObjectIdentifier(str);
        for (SignerInf toSignerInfoGenerator : this.signerInfs) {
            try {
                this.signerGens.add(toSignerInfoGenerator.toSignerInfoGenerator(this.rand, provider, z2));
            } catch (Exception e) {
                throw new CMSException("exception creating signerInf", e);
            } catch (Exception e2) {
                throw new CMSException("exception encoding attributes", e2);
            } catch (Exception e22) {
                throw new CMSException("error creating sid.", e22);
            }
        }
        this.signerInfs.clear();
        return cMSProcessable != null ? generate(new CMSTypedData() {
            public Object getContent() {
                return cMSProcessable.getContent();
            }

            public ASN1ObjectIdentifier getContentType() {
                return aSN1ObjectIdentifier;
            }

            public void write(OutputStream outputStream) throws IOException, CMSException {
                cMSProcessable.write(outputStream);
            }
        }, z) : generate(new CMSAbsentContent(aSN1ObjectIdentifier), z);
    }

    public CMSSignedData generate(CMSProcessable cMSProcessable, String str) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return generate(cMSProcessable, CMSUtils.getProvider(str));
    }

    public CMSSignedData generate(CMSProcessable cMSProcessable, Provider provider) throws NoSuchAlgorithmException, CMSException {
        return generate(cMSProcessable, false, provider);
    }

    public CMSSignedData generate(CMSProcessable cMSProcessable, boolean z, String str) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return cMSProcessable instanceof CMSTypedData ? generate(((CMSTypedData) cMSProcessable).getContentType().getId(), cMSProcessable, z, str) : generate(DATA, cMSProcessable, z, str);
    }

    public CMSSignedData generate(CMSProcessable cMSProcessable, boolean z, Provider provider) throws NoSuchAlgorithmException, CMSException {
        return cMSProcessable instanceof CMSTypedData ? generate(((CMSTypedData) cMSProcessable).getContentType().getId(), cMSProcessable, z, provider) : generate(DATA, cMSProcessable, z, provider);
    }

    public CMSSignedData generate(CMSTypedData cMSTypedData) throws CMSException {
        return generate(cMSTypedData, false);
    }

    public CMSSignedData generate(CMSTypedData cMSTypedData, boolean z) throws CMSException {
        if (this.signerInfs.isEmpty()) {
            ASN1Encodable bEROctetString;
            Object generate;
            Object calculatedDigest;
            ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
            ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
            this.digests.clear();
            for (SignerInformation signerInformation : this._signers) {
                aSN1EncodableVector.add(CMSSignedHelper.INSTANCE.fixAlgID(signerInformation.getDigestAlgorithmID()));
                aSN1EncodableVector2.add(signerInformation.toASN1Structure());
            }
            ASN1ObjectIdentifier contentType = cMSTypedData.getContentType();
            if (cMSTypedData != null) {
                OutputStream byteArrayOutputStream = z ? new ByteArrayOutputStream() : null;
                OutputStream safeOutputStream = CMSUtils.getSafeOutputStream(CMSUtils.attachSignersToOutputStream(this.signerGens, byteArrayOutputStream));
                try {
                    cMSTypedData.write(safeOutputStream);
                    safeOutputStream.close();
                    if (z) {
                        bEROctetString = new BEROctetString(byteArrayOutputStream.toByteArray());
                        for (SignerInfoGenerator signerInfoGenerator : this.signerGens) {
                            generate = signerInfoGenerator.generate(contentType);
                            aSN1EncodableVector.add(generate.getDigestAlgorithm());
                            aSN1EncodableVector2.add(generate);
                            calculatedDigest = signerInfoGenerator.getCalculatedDigest();
                            if (calculatedDigest != null) {
                                this.digests.put(generate.getDigestAlgorithm().getAlgorithm().getId(), calculatedDigest);
                            }
                        }
                        return new CMSSignedData((CMSProcessable) cMSTypedData, new ContentInfo(CMSObjectIdentifiers.signedData, new SignedData(new DERSet(aSN1EncodableVector), new ContentInfo(contentType, bEROctetString), this.certs.size() == 0 ? CMSUtils.createBerSetFromList(this.certs) : null, this.crls.size() == 0 ? CMSUtils.createBerSetFromList(this.crls) : null, new DERSet(aSN1EncodableVector2))));
                    }
                } catch (Exception e) {
                    throw new CMSException("data processing exception: " + e.getMessage(), e);
                }
            }
            bEROctetString = null;
            for (SignerInfoGenerator signerInfoGenerator2 : this.signerGens) {
                generate = signerInfoGenerator2.generate(contentType);
                aSN1EncodableVector.add(generate.getDigestAlgorithm());
                aSN1EncodableVector2.add(generate);
                calculatedDigest = signerInfoGenerator2.getCalculatedDigest();
                if (calculatedDigest != null) {
                    this.digests.put(generate.getDigestAlgorithm().getAlgorithm().getId(), calculatedDigest);
                }
            }
            if (this.certs.size() == 0) {
            }
            if (this.crls.size() == 0) {
            }
            return new CMSSignedData((CMSProcessable) cMSTypedData, new ContentInfo(CMSObjectIdentifiers.signedData, new SignedData(new DERSet(aSN1EncodableVector), new ContentInfo(contentType, bEROctetString), this.certs.size() == 0 ? CMSUtils.createBerSetFromList(this.certs) : null, this.crls.size() == 0 ? CMSUtils.createBerSetFromList(this.crls) : null, new DERSet(aSN1EncodableVector2))));
        }
        throw new IllegalStateException("this method can only be used with SignerInfoGenerator");
    }

    public SignerInformationStore generateCounterSigners(SignerInformation signerInformation) throws CMSException {
        return generate(new CMSProcessableByteArray(null, signerInformation.getSignature()), false).getSignerInfos();
    }

    public SignerInformationStore generateCounterSigners(SignerInformation signerInformation, String str) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return generate(null, new CMSProcessableByteArray(signerInformation.getSignature()), false, CMSUtils.getProvider(str)).getSignerInfos();
    }

    public SignerInformationStore generateCounterSigners(SignerInformation signerInformation, Provider provider) throws NoSuchAlgorithmException, CMSException {
        return generate(null, new CMSProcessableByteArray(signerInformation.getSignature()), false, provider).getSignerInfos();
    }
}
