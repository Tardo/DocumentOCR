package org.bouncycastle.tsp.cms;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.TimeStampAndCRL;
import org.bouncycastle.asn1.cms.TimeStampedData;
import org.bouncycastle.asn1.cms.TimeStampedDataParser;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;

class TimeStampDataUtil {
    private final MetaDataUtil metaDataUtil;
    private final TimeStampAndCRL[] timeStamps;

    TimeStampDataUtil(TimeStampedData timeStampedData) {
        this.metaDataUtil = new MetaDataUtil(timeStampedData.getMetaData());
        this.timeStamps = timeStampedData.getTemporalEvidence().getTstEvidence().toTimeStampAndCRLArray();
    }

    TimeStampDataUtil(TimeStampedDataParser timeStampedDataParser) throws IOException {
        this.metaDataUtil = new MetaDataUtil(timeStampedDataParser.getMetaData());
        this.timeStamps = timeStampedDataParser.getTemporalEvidence().getTstEvidence().toTimeStampAndCRLArray();
    }

    private void compareDigest(TimeStampToken timeStampToken, byte[] bArr) throws ImprintDigestInvalidException {
        if (!Arrays.areEqual(bArr, timeStampToken.getTimeStampInfo().getMessageImprintDigest())) {
            throw new ImprintDigestInvalidException("hash calculated is different from MessageImprintDigest found in TimeStampToken", timeStampToken);
        }
    }

    byte[] calculateNextHash(DigestCalculator digestCalculator) throws CMSException {
        TimeStampAndCRL timeStampAndCRL = this.timeStamps[this.timeStamps.length - 1];
        OutputStream outputStream = digestCalculator.getOutputStream();
        try {
            outputStream.write(timeStampAndCRL.getEncoded("DER"));
            outputStream.close();
            return digestCalculator.getDigest();
        } catch (Exception e) {
            throw new CMSException("exception calculating hash: " + e.getMessage(), e);
        }
    }

    String getFileName() {
        return this.metaDataUtil.getFileName();
    }

    String getMediaType() {
        return this.metaDataUtil.getMediaType();
    }

    DigestCalculator getMessageImprintDigestCalculator(DigestCalculatorProvider digestCalculatorProvider) throws OperatorCreationException {
        try {
            DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(getTimeStampToken(this.timeStamps[0]).getTimeStampInfo().getMessageImprintAlgOID()));
            initialiseMessageImprintDigestCalculator(digestCalculator);
            return digestCalculator;
        } catch (Throwable e) {
            throw new OperatorCreationException("unable to extract algorithm ID: " + e.getMessage(), e);
        }
    }

    AttributeTable getOtherMetaData() {
        return new AttributeTable(this.metaDataUtil.getOtherMetaData());
    }

    TimeStampToken getTimeStampToken(TimeStampAndCRL timeStampAndCRL) throws CMSException {
        try {
            return new TimeStampToken(timeStampAndCRL.getTimeStampToken());
        } catch (Exception e) {
            throw new CMSException("unable to parse token data: " + e.getMessage(), e);
        } catch (Exception e2) {
            if (e2.getCause() instanceof CMSException) {
                throw ((CMSException) e2.getCause());
            }
            throw new CMSException("token data invalid: " + e2.getMessage(), e2);
        } catch (Exception e22) {
            throw new CMSException("token data invalid: " + e22.getMessage(), e22);
        }
    }

    TimeStampToken[] getTimeStampTokens() throws CMSException {
        TimeStampToken[] timeStampTokenArr = new TimeStampToken[this.timeStamps.length];
        for (int i = 0; i < this.timeStamps.length; i++) {
            timeStampTokenArr[i] = getTimeStampToken(this.timeStamps[i]);
        }
        return timeStampTokenArr;
    }

    TimeStampAndCRL[] getTimeStamps() {
        return this.timeStamps;
    }

    void initialiseMessageImprintDigestCalculator(DigestCalculator digestCalculator) throws CMSException {
        this.metaDataUtil.initialiseMessageImprintDigestCalculator(digestCalculator);
    }

    void validate(DigestCalculatorProvider digestCalculatorProvider, byte[] bArr) throws ImprintDigestInvalidException, CMSException {
        int i = 0;
        while (i < this.timeStamps.length) {
            try {
                TimeStampToken timeStampToken = getTimeStampToken(this.timeStamps[i]);
                if (i > 0) {
                    DigestCalculator digestCalculator = digestCalculatorProvider.get(timeStampToken.getTimeStampInfo().getHashAlgorithm());
                    digestCalculator.getOutputStream().write(this.timeStamps[i - 1].getEncoded("DER"));
                    bArr = digestCalculator.getDigest();
                }
                compareDigest(timeStampToken, bArr);
                i++;
            } catch (Exception e) {
                throw new CMSException("exception calculating hash: " + e.getMessage(), e);
            } catch (Exception e2) {
                throw new CMSException("cannot create digest: " + e2.getMessage(), e2);
            }
        }
    }

    void validate(DigestCalculatorProvider digestCalculatorProvider, byte[] bArr, TimeStampToken timeStampToken) throws ImprintDigestInvalidException, CMSException {
        try {
            byte[] encoded = timeStampToken.getEncoded();
            int i = 0;
            while (i < this.timeStamps.length) {
                try {
                    TimeStampToken timeStampToken2 = getTimeStampToken(this.timeStamps[i]);
                    if (i > 0) {
                        DigestCalculator digestCalculator = digestCalculatorProvider.get(timeStampToken2.getTimeStampInfo().getHashAlgorithm());
                        digestCalculator.getOutputStream().write(this.timeStamps[i - 1].getEncoded("DER"));
                        bArr = digestCalculator.getDigest();
                    }
                    compareDigest(timeStampToken2, bArr);
                    if (!Arrays.areEqual(timeStampToken2.getEncoded(), encoded)) {
                        i++;
                    } else {
                        return;
                    }
                } catch (Exception e) {
                    throw new CMSException("exception calculating hash: " + e.getMessage(), e);
                } catch (Exception e2) {
                    throw new CMSException("cannot create digest: " + e2.getMessage(), e2);
                }
            }
            throw new ImprintDigestInvalidException("passed in token not associated with timestamps present", timeStampToken);
        } catch (Exception e22) {
            throw new CMSException("exception encoding timeStampToken: " + e22.getMessage(), e22);
        }
    }
}