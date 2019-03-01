package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.util.io.TeeOutputStream;

public class CMSAuthenticatedDataStreamGenerator extends CMSAuthenticatedGenerator {
    private boolean berEncodeRecipientSet;
    private int bufferSize;
    private MacCalculator macCalculator;

    private class CmsAuthenticatedDataOutputStream extends OutputStream {
        private BERSequenceGenerator cGen;
        private ASN1ObjectIdentifier contentType;
        private OutputStream dataStream;
        private DigestCalculator digestCalculator;
        private BERSequenceGenerator eiGen;
        private BERSequenceGenerator envGen;
        private MacCalculator macCalculator;

        public CmsAuthenticatedDataOutputStream(MacCalculator macCalculator, DigestCalculator digestCalculator, ASN1ObjectIdentifier aSN1ObjectIdentifier, OutputStream outputStream, BERSequenceGenerator bERSequenceGenerator, BERSequenceGenerator bERSequenceGenerator2, BERSequenceGenerator bERSequenceGenerator3) {
            this.macCalculator = macCalculator;
            this.digestCalculator = digestCalculator;
            this.contentType = aSN1ObjectIdentifier;
            this.dataStream = outputStream;
            this.cGen = bERSequenceGenerator;
            this.envGen = bERSequenceGenerator2;
            this.eiGen = bERSequenceGenerator3;
        }

        public void close() throws IOException {
            Map unmodifiableMap;
            this.dataStream.close();
            this.eiGen.close();
            if (this.digestCalculator != null) {
                unmodifiableMap = Collections.unmodifiableMap(CMSAuthenticatedDataStreamGenerator.this.getBaseParameters(this.contentType, this.digestCalculator.getAlgorithmIdentifier(), this.digestCalculator.getDigest()));
                if (CMSAuthenticatedDataStreamGenerator.this.authGen == null) {
                    CMSAuthenticatedDataStreamGenerator.this.authGen = new DefaultAuthenticatedAttributeTableGenerator();
                }
                ASN1Encodable dERSet = new DERSet(CMSAuthenticatedDataStreamGenerator.this.authGen.getAttributes(unmodifiableMap).toASN1EncodableVector());
                OutputStream outputStream = this.macCalculator.getOutputStream();
                outputStream.write(dERSet.getEncoded("DER"));
                outputStream.close();
                this.envGen.addObject(new DERTaggedObject(false, 2, dERSet));
            } else {
                unmodifiableMap = Collections.unmodifiableMap(new HashMap());
            }
            this.envGen.addObject(new DEROctetString(this.macCalculator.getMac()));
            if (CMSAuthenticatedDataStreamGenerator.this.unauthGen != null) {
                this.envGen.addObject(new DERTaggedObject(false, 3, new BERSet(CMSAuthenticatedDataStreamGenerator.this.unauthGen.getAttributes(unmodifiableMap).toASN1EncodableVector())));
            }
            this.envGen.close();
            this.cGen.close();
        }

        public void write(int i) throws IOException {
            this.dataStream.write(i);
        }

        public void write(byte[] bArr) throws IOException {
            this.dataStream.write(bArr);
        }

        public void write(byte[] bArr, int i, int i2) throws IOException {
            this.dataStream.write(bArr, i, i2);
        }
    }

    public CMSAuthenticatedDataStreamGenerator(SecureRandom secureRandom) {
        super(secureRandom);
    }

    public OutputStream open(OutputStream outputStream, String str, int i, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException {
        convertOldRecipients(this.rand, CMSUtils.getProvider(str2));
        return open(outputStream, new JceCMSMacCalculatorBuilder(new ASN1ObjectIdentifier(str), i).setSecureRandom(this.rand).setProvider(str2).build());
    }

    public OutputStream open(OutputStream outputStream, String str, int i, Provider provider) throws NoSuchAlgorithmException, CMSException, IOException {
        convertOldRecipients(this.rand, provider);
        return open(outputStream, new JceCMSMacCalculatorBuilder(new ASN1ObjectIdentifier(str), i).setSecureRandom(this.rand).setProvider(provider).build());
    }

    public OutputStream open(OutputStream outputStream, String str, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException {
        convertOldRecipients(this.rand, CMSUtils.getProvider(str2));
        return open(outputStream, new JceCMSMacCalculatorBuilder(new ASN1ObjectIdentifier(str)).setSecureRandom(this.rand).setProvider(str2).build());
    }

    public OutputStream open(OutputStream outputStream, String str, Provider provider) throws NoSuchAlgorithmException, CMSException, IOException {
        convertOldRecipients(this.rand, provider);
        return open(outputStream, new JceCMSMacCalculatorBuilder(new ASN1ObjectIdentifier(str)).setSecureRandom(this.rand).setProvider(provider).build());
    }

    public OutputStream open(OutputStream outputStream, MacCalculator macCalculator) throws CMSException {
        return open(CMSObjectIdentifiers.data, outputStream, macCalculator);
    }

    public OutputStream open(OutputStream outputStream, MacCalculator macCalculator, DigestCalculator digestCalculator) throws CMSException {
        return open(CMSObjectIdentifiers.data, outputStream, macCalculator, digestCalculator);
    }

    public OutputStream open(ASN1ObjectIdentifier aSN1ObjectIdentifier, OutputStream outputStream, MacCalculator macCalculator) throws CMSException {
        return open(aSN1ObjectIdentifier, outputStream, macCalculator, null);
    }

    public OutputStream open(ASN1ObjectIdentifier aSN1ObjectIdentifier, OutputStream outputStream, MacCalculator macCalculator, DigestCalculator digestCalculator) throws CMSException {
        this.macCalculator = macCalculator;
        try {
            ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
            for (RecipientInfoGenerator generate : this.recipientInfoGenerators) {
                aSN1EncodableVector.add(generate.generate(macCalculator.getKey()));
            }
            BERSequenceGenerator bERSequenceGenerator = new BERSequenceGenerator(outputStream);
            bERSequenceGenerator.addObject(CMSObjectIdentifiers.authenticatedData);
            BERSequenceGenerator bERSequenceGenerator2 = new BERSequenceGenerator(bERSequenceGenerator.getRawOutputStream(), 0, true);
            bERSequenceGenerator2.addObject(new DERInteger((long) AuthenticatedData.calculateVersion(this.originatorInfo)));
            if (this.originatorInfo != null) {
                bERSequenceGenerator2.addObject(new DERTaggedObject(false, 0, this.originatorInfo));
            }
            if (this.berEncodeRecipientSet) {
                bERSequenceGenerator2.getRawOutputStream().write(new BERSet(aSN1EncodableVector).getEncoded());
            } else {
                bERSequenceGenerator2.getRawOutputStream().write(new DERSet(aSN1EncodableVector).getEncoded());
            }
            bERSequenceGenerator2.getRawOutputStream().write(macCalculator.getAlgorithmIdentifier().getEncoded());
            if (digestCalculator != null) {
                bERSequenceGenerator2.addObject(new DERTaggedObject(false, 1, digestCalculator.getAlgorithmIdentifier()));
            }
            BERSequenceGenerator bERSequenceGenerator3 = new BERSequenceGenerator(bERSequenceGenerator2.getRawOutputStream());
            bERSequenceGenerator3.addObject(aSN1ObjectIdentifier);
            OutputStream createBEROctetOutputStream = CMSUtils.createBEROctetOutputStream(bERSequenceGenerator3.getRawOutputStream(), 0, false, this.bufferSize);
            return new CmsAuthenticatedDataOutputStream(macCalculator, digestCalculator, aSN1ObjectIdentifier, digestCalculator != null ? new TeeOutputStream(createBEROctetOutputStream, digestCalculator.getOutputStream()) : new TeeOutputStream(createBEROctetOutputStream, macCalculator.getOutputStream()), bERSequenceGenerator, bERSequenceGenerator2, bERSequenceGenerator3);
        } catch (Exception e) {
            throw new CMSException("exception decoding algorithm parameters.", e);
        }
    }

    public void setBEREncodeRecipients(boolean z) {
        this.berEncodeRecipientSet = z;
    }

    public void setBufferSize(int i) {
        this.bufferSize = i;
    }
}
