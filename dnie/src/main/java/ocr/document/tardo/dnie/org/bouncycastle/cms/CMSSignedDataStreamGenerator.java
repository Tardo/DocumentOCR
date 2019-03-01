package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class CMSSignedDataStreamGenerator extends CMSSignedGenerator {
    private int _bufferSize;

    private class CmsSignedDataOutputStream extends OutputStream {
        private ASN1ObjectIdentifier _contentOID;
        private BERSequenceGenerator _eiGen;
        private OutputStream _out;
        private BERSequenceGenerator _sGen;
        private BERSequenceGenerator _sigGen;

        public CmsSignedDataOutputStream(OutputStream outputStream, ASN1ObjectIdentifier aSN1ObjectIdentifier, BERSequenceGenerator bERSequenceGenerator, BERSequenceGenerator bERSequenceGenerator2, BERSequenceGenerator bERSequenceGenerator3) {
            this._out = outputStream;
            this._contentOID = aSN1ObjectIdentifier;
            this._sGen = bERSequenceGenerator;
            this._sigGen = bERSequenceGenerator2;
            this._eiGen = bERSequenceGenerator3;
        }

        public void close() throws IOException {
            this._out.close();
            this._eiGen.close();
            CMSSignedDataStreamGenerator.this.digests.clear();
            if (CMSSignedDataStreamGenerator.this.certs.size() != 0) {
                this._sigGen.getRawOutputStream().write(new BERTaggedObject(false, 0, CMSUtils.createBerSetFromList(CMSSignedDataStreamGenerator.this.certs)).getEncoded());
            }
            if (CMSSignedDataStreamGenerator.this.crls.size() != 0) {
                this._sigGen.getRawOutputStream().write(new BERTaggedObject(false, 1, CMSUtils.createBerSetFromList(CMSSignedDataStreamGenerator.this.crls)).getEncoded());
            }
            ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
            for (SignerInfoGenerator signerInfoGenerator : CMSSignedDataStreamGenerator.this.signerGens) {
                try {
                    aSN1EncodableVector.add(signerInfoGenerator.generate(this._contentOID));
                    CMSSignedDataStreamGenerator.this.digests.put(signerInfoGenerator.getDigestAlgorithm().getAlgorithm().getId(), signerInfoGenerator.getCalculatedDigest());
                } catch (Throwable e) {
                    throw new CMSStreamException("exception generating signers: " + e.getMessage(), e);
                }
            }
            for (SignerInformation toASN1Structure : CMSSignedDataStreamGenerator.this._signers) {
                aSN1EncodableVector.add(toASN1Structure.toASN1Structure());
            }
            this._sigGen.getRawOutputStream().write(new DERSet(aSN1EncodableVector).getEncoded());
            this._sigGen.close();
            this._sGen.close();
        }

        public void write(int i) throws IOException {
            this._out.write(i);
        }

        public void write(byte[] bArr) throws IOException {
            this._out.write(bArr);
        }

        public void write(byte[] bArr, int i, int i2) throws IOException {
            this._out.write(bArr, i, i2);
        }
    }

    public CMSSignedDataStreamGenerator(SecureRandom secureRandom) {
        super(secureRandom);
    }

    private ASN1Integer calculateVersion(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        Object obj;
        Object obj2;
        Object obj3;
        Object obj4 = null;
        if (this.certs != null) {
            obj = null;
            obj2 = null;
            obj3 = null;
            for (Object next : this.certs) {
                Object next2;
                if (next2 instanceof ASN1TaggedObject) {
                    ASN1TaggedObject aSN1TaggedObject = (ASN1TaggedObject) next2;
                    if (aSN1TaggedObject.getTagNo() == 1) {
                        next2 = obj;
                        obj2 = obj3;
                        obj = 1;
                    } else if (aSN1TaggedObject.getTagNo() == 2) {
                        int i = 1;
                        obj = obj2;
                        obj2 = obj3;
                    } else if (aSN1TaggedObject.getTagNo() == 3) {
                        next2 = obj;
                        obj = obj2;
                        int i2 = 1;
                    }
                    obj3 = obj2;
                    obj2 = obj;
                    obj = next2;
                }
                next2 = obj;
                obj = obj2;
                obj2 = obj3;
                obj3 = obj2;
                obj2 = obj;
                obj = next2;
            }
        } else {
            obj = null;
            obj2 = null;
            obj3 = null;
        }
        if (obj3 != null) {
            return new ASN1Integer(5);
        }
        if (this.crls != null) {
            for (Object obj32 : this.crls) {
                if (obj32 instanceof ASN1TaggedObject) {
                    obj4 = 1;
                }
            }
        }
        return obj4 != null ? new ASN1Integer(5) : obj != null ? new ASN1Integer(4) : obj2 != null ? new ASN1Integer(3) : checkForVersion3(this._signers, this.signerGens) ? new ASN1Integer(3) : !CMSObjectIdentifiers.data.equals(aSN1ObjectIdentifier) ? new ASN1Integer(3) : new ASN1Integer(1);
    }

    private boolean checkForVersion3(List list, List list2) {
        for (SignerInformation toASN1Structure : list) {
            if (SignerInfo.getInstance(toASN1Structure.toASN1Structure()).getVersion().getValue().intValue() == 3) {
                return true;
            }
        }
        for (SignerInfoGenerator generatedVersion : list2) {
            if (generatedVersion.getGeneratedVersion().getValue().intValue() == 3) {
                return true;
            }
        }
        return false;
    }

    private void doAddSigner(PrivateKey privateKey, Object obj, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, Provider provider, Provider provider2) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            JcaContentSignerBuilder secureRandom = new JcaContentSignerBuilder(CMSSignedHelper.INSTANCE.getDigestAlgName(str2) + "with" + CMSSignedHelper.INSTANCE.getEncryptionAlgName(str)).setSecureRandom(this.rand);
            if (provider != null) {
                secureRandom.setProvider(provider);
            }
            try {
                JcaDigestCalculatorProviderBuilder jcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
                if (!(provider2 == null || provider2.getName().equalsIgnoreCase("SunRsaSign"))) {
                    jcaDigestCalculatorProviderBuilder.setProvider(provider2);
                }
                JcaSignerInfoGeneratorBuilder jcaSignerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(jcaDigestCalculatorProviderBuilder.build());
                jcaSignerInfoGeneratorBuilder.setSignedAttributeGenerator(cMSAttributeTableGenerator);
                jcaSignerInfoGeneratorBuilder.setUnsignedAttributeGenerator(cMSAttributeTableGenerator2);
                ContentSigner build = secureRandom.build(privateKey);
                if (obj instanceof X509Certificate) {
                    addSignerInfoGenerator(jcaSignerInfoGeneratorBuilder.build(build, (X509Certificate) obj));
                } else {
                    addSignerInfoGenerator(jcaSignerInfoGeneratorBuilder.build(build, (byte[]) obj));
                }
            } catch (OperatorCreationException e) {
                if (e.getCause() instanceof NoSuchAlgorithmException) {
                    throw ((NoSuchAlgorithmException) e.getCause());
                } else if (e.getCause() instanceof InvalidKeyException) {
                    throw ((InvalidKeyException) e.getCause());
                }
            } catch (CertificateEncodingException e2) {
                throw new IllegalStateException("unable to encode certificate");
            } catch (OperatorCreationException e3) {
                throw new NoSuchAlgorithmException("unable to create operators: " + e3.getMessage());
            }
        } catch (IllegalArgumentException e4) {
            throw new NoSuchAlgorithmException(e4.getMessage());
        }
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, CMSUtils.getProvider(str2));
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2, String str3) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, str2, CMSUtils.getProvider(str3));
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2, Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, str2, new DefaultSignedAttributeTableGenerator(), (CMSAttributeTableGenerator) null, provider);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2, AttributeTable attributeTable, AttributeTable attributeTable2, String str3) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, str2, attributeTable, attributeTable2, CMSUtils.getProvider(str3));
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2, AttributeTable attributeTable, AttributeTable attributeTable2, Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, str2, new DefaultSignedAttributeTableGenerator(attributeTable), new SimpleAttributeTableGenerator(attributeTable2), provider);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, String str3) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, str2, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, CMSUtils.getProvider(str3));
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, str2, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, provider, provider);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, Provider provider, Provider provider2) throws NoSuchAlgorithmException, InvalidKeyException {
        doAddSigner(privateKey, x509Certificate, str, str2, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, provider, provider2);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, new DefaultSignedAttributeTableGenerator(), (CMSAttributeTableGenerator) null, provider);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, AttributeTable attributeTable, AttributeTable attributeTable2, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, attributeTable, attributeTable2, CMSUtils.getProvider(str2));
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, AttributeTable attributeTable, AttributeTable attributeTable2, Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, new DefaultSignedAttributeTableGenerator(attributeTable), new SimpleAttributeTableGenerator(attributeTable2), provider);
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, str, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, CMSUtils.getProvider(str2));
    }

    public void addSigner(PrivateKey privateKey, X509Certificate x509Certificate, String str, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        addSigner(privateKey, x509Certificate, getEncOID(privateKey, str), str, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, provider);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, bArr, str, CMSUtils.getProvider(str2));
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, String str2, String str3) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, bArr, str, str2, CMSUtils.getProvider(str3));
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, String str2, Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, bArr, str, str2, new DefaultSignedAttributeTableGenerator(), (CMSAttributeTableGenerator) null, provider);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, String str3) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, bArr, str, str2, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, CMSUtils.getProvider(str3));
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        addSigner(privateKey, bArr, str, str2, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, provider, provider);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, String str2, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, Provider provider, Provider provider2) throws NoSuchAlgorithmException, InvalidKeyException {
        doAddSigner(privateKey, bArr, str, str2, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, provider, provider2);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, bArr, str, new DefaultSignedAttributeTableGenerator(), (CMSAttributeTableGenerator) null, provider);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, AttributeTable attributeTable, AttributeTable attributeTable2, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, bArr, str, attributeTable, attributeTable2, CMSUtils.getProvider(str2));
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, AttributeTable attributeTable, AttributeTable attributeTable2, Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        addSigner(privateKey, bArr, str, new DefaultSignedAttributeTableGenerator(attributeTable), new SimpleAttributeTableGenerator(attributeTable2), provider);
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        addSigner(privateKey, bArr, str, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, CMSUtils.getProvider(str2));
    }

    public void addSigner(PrivateKey privateKey, byte[] bArr, String str, CMSAttributeTableGenerator cMSAttributeTableGenerator, CMSAttributeTableGenerator cMSAttributeTableGenerator2, Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        addSigner(privateKey, bArr, getEncOID(privateKey, str), str, cMSAttributeTableGenerator, cMSAttributeTableGenerator2, provider);
    }

    void generate(OutputStream outputStream, String str, boolean z, OutputStream outputStream2, CMSProcessable cMSProcessable) throws CMSException, IOException {
        OutputStream open = open(outputStream, str, z, outputStream2);
        if (cMSProcessable != null) {
            cMSProcessable.write(open);
        }
        open.close();
    }

    public OutputStream open(OutputStream outputStream) throws IOException {
        return open(outputStream, false);
    }

    public OutputStream open(OutputStream outputStream, String str, boolean z) throws IOException {
        return open(outputStream, str, z, null);
    }

    public OutputStream open(OutputStream outputStream, String str, boolean z, OutputStream outputStream2) throws IOException {
        return open(new ASN1ObjectIdentifier(str), outputStream, z, outputStream2);
    }

    public OutputStream open(OutputStream outputStream, boolean z) throws IOException {
        return open(CMSObjectIdentifiers.data, outputStream, z);
    }

    public OutputStream open(OutputStream outputStream, boolean z, OutputStream outputStream2) throws IOException {
        return open(CMSObjectIdentifiers.data, outputStream, z, outputStream2);
    }

    public OutputStream open(ASN1ObjectIdentifier aSN1ObjectIdentifier, OutputStream outputStream, boolean z) throws IOException {
        return open(aSN1ObjectIdentifier, outputStream, z, null);
    }

    public OutputStream open(ASN1ObjectIdentifier aSN1ObjectIdentifier, OutputStream outputStream, boolean z, OutputStream outputStream2) throws IOException {
        BERSequenceGenerator bERSequenceGenerator = new BERSequenceGenerator(outputStream);
        bERSequenceGenerator.addObject(CMSObjectIdentifiers.signedData);
        BERSequenceGenerator bERSequenceGenerator2 = new BERSequenceGenerator(bERSequenceGenerator.getRawOutputStream(), 0, true);
        bERSequenceGenerator2.addObject(calculateVersion(aSN1ObjectIdentifier));
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        for (SignerInformation digestAlgorithmID : this._signers) {
            aSN1EncodableVector.add(CMSSignedHelper.INSTANCE.fixAlgID(digestAlgorithmID.getDigestAlgorithmID()));
        }
        for (SignerInfoGenerator digestAlgorithm : this.signerGens) {
            aSN1EncodableVector.add(digestAlgorithm.getDigestAlgorithm());
        }
        bERSequenceGenerator2.getRawOutputStream().write(new DERSet(aSN1EncodableVector).getEncoded());
        BERSequenceGenerator bERSequenceGenerator3 = new BERSequenceGenerator(bERSequenceGenerator2.getRawOutputStream());
        bERSequenceGenerator3.addObject(aSN1ObjectIdentifier);
        return new CmsSignedDataOutputStream(CMSUtils.attachSignersToOutputStream(this.signerGens, CMSUtils.getSafeTeeOutputStream(outputStream2, z ? CMSUtils.createBEROctetOutputStream(bERSequenceGenerator3.getRawOutputStream(), 0, true, this._bufferSize) : null)), aSN1ObjectIdentifier, bERSequenceGenerator, bERSequenceGenerator2, bERSequenceGenerator3);
    }

    public void setBufferSize(int i) {
        this._bufferSize = i;
    }
}
