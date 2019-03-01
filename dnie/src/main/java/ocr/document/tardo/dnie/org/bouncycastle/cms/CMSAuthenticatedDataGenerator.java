package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.TeeOutputStream;

public class CMSAuthenticatedDataGenerator extends CMSAuthenticatedGenerator {
    public CMSAuthenticatedDataGenerator(SecureRandom secureRandom) {
        super(secureRandom);
    }

    private CMSAuthenticatedData generate(final CMSProcessable cMSProcessable, String str, KeyGenerator keyGenerator, Provider provider) throws NoSuchAlgorithmException, CMSException {
        Provider provider2 = keyGenerator.getProvider();
        convertOldRecipients(this.rand, provider);
        return generate(new CMSTypedData() {
            public Object getContent() {
                return cMSProcessable;
            }

            public ASN1ObjectIdentifier getContentType() {
                return CMSObjectIdentifiers.data;
            }

            public void write(OutputStream outputStream) throws IOException, CMSException {
                cMSProcessable.write(outputStream);
            }
        }, new JceCMSMacCalculatorBuilder(new ASN1ObjectIdentifier(str)).setProvider(provider2).setSecureRandom(this.rand).build());
    }

    public CMSAuthenticatedData generate(CMSProcessable cMSProcessable, String str, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return generate(cMSProcessable, str, CMSUtils.getProvider(str2));
    }

    public CMSAuthenticatedData generate(CMSProcessable cMSProcessable, String str, Provider provider) throws NoSuchAlgorithmException, CMSException {
        return generate(cMSProcessable, str, CMSEnvelopedHelper.INSTANCE.createSymmetricKeyGenerator(str, provider), provider);
    }

    public CMSAuthenticatedData generate(CMSTypedData cMSTypedData, MacCalculator macCalculator) throws CMSException {
        return generate(cMSTypedData, macCalculator, null);
    }

    public CMSAuthenticatedData generate(CMSTypedData cMSTypedData, MacCalculator macCalculator, final DigestCalculator digestCalculator) throws CMSException {
        ASN1Encodable authenticatedData;
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        for (RecipientInfoGenerator generate : this.recipientInfoGenerators) {
            aSN1EncodableVector.add(generate.generate(macCalculator.getKey()));
        }
        if (digestCalculator != null) {
            try {
                OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                OutputStream teeOutputStream = new TeeOutputStream(digestCalculator.getOutputStream(), byteArrayOutputStream);
                cMSTypedData.write(teeOutputStream);
                teeOutputStream.close();
                ASN1Encodable bEROctetString = new BEROctetString(byteArrayOutputStream.toByteArray());
                Map baseParameters = getBaseParameters(cMSTypedData.getContentType(), digestCalculator.getAlgorithmIdentifier(), digestCalculator.getDigest());
                if (this.authGen == null) {
                    this.authGen = new DefaultAuthenticatedAttributeTableGenerator();
                }
                ASN1Set dERSet = new DERSet(this.authGen.getAttributes(Collections.unmodifiableMap(baseParameters)).toASN1EncodableVector());
                try {
                    OutputStream outputStream = macCalculator.getOutputStream();
                    outputStream.write(dERSet.getEncoded("DER"));
                    outputStream.close();
                    authenticatedData = new AuthenticatedData(this.originatorInfo, new DERSet(aSN1EncodableVector), macCalculator.getAlgorithmIdentifier(), digestCalculator.getAlgorithmIdentifier(), new ContentInfo(CMSObjectIdentifiers.data, bEROctetString), dERSet, new DEROctetString(macCalculator.getMac()), this.unauthGen != null ? new BERSet(this.unauthGen.getAttributes(Collections.unmodifiableMap(baseParameters)).toASN1EncodableVector()) : null);
                } catch (Exception e) {
                    throw new CMSException("exception decoding algorithm parameters.", e);
                }
            } catch (Exception e2) {
                throw new CMSException("unable to perform digest calculation: " + e2.getMessage(), e2);
            }
        }
        try {
            byteArrayOutputStream = new ByteArrayOutputStream();
            teeOutputStream = new TeeOutputStream(byteArrayOutputStream, macCalculator.getOutputStream());
            cMSTypedData.write(teeOutputStream);
            teeOutputStream.close();
            authenticatedData = new AuthenticatedData(this.originatorInfo, new DERSet(aSN1EncodableVector), macCalculator.getAlgorithmIdentifier(), null, new ContentInfo(CMSObjectIdentifiers.data, new BEROctetString(byteArrayOutputStream.toByteArray())), null, new DEROctetString(macCalculator.getMac()), this.unauthGen != null ? new BERSet(this.unauthGen.getAttributes(new HashMap()).toASN1EncodableVector()) : null);
        } catch (Exception e22) {
            throw new CMSException("exception decoding algorithm parameters.", e22);
        }
        return new CMSAuthenticatedData(new ContentInfo(CMSObjectIdentifiers.authenticatedData, authenticatedData), new DigestCalculatorProvider() {
            public DigestCalculator get(AlgorithmIdentifier algorithmIdentifier) throws OperatorCreationException {
                return digestCalculator;
            }
        });
    }
}
