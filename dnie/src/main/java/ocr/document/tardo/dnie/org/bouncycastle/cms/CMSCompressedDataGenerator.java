package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.zip.DeflaterOutputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.CompressedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.OutputCompressor;

public class CMSCompressedDataGenerator {
    public static final String ZLIB = "1.2.840.113549.1.9.16.3.8";

    public CMSCompressedData generate(CMSProcessable cMSProcessable, String str) throws CMSException {
        try {
            OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            OutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream);
            cMSProcessable.write(deflaterOutputStream);
            deflaterOutputStream.close();
            return new CMSCompressedData(new ContentInfo(CMSObjectIdentifiers.compressedData, new CompressedData(new AlgorithmIdentifier(new ASN1ObjectIdentifier(str)), new ContentInfo(CMSObjectIdentifiers.data, new BEROctetString(byteArrayOutputStream.toByteArray())))));
        } catch (Exception e) {
            throw new CMSException("exception encoding data.", e);
        }
    }

    public CMSCompressedData generate(CMSTypedData cMSTypedData, OutputCompressor outputCompressor) throws CMSException {
        try {
            OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            OutputStream outputStream = outputCompressor.getOutputStream(byteArrayOutputStream);
            cMSTypedData.write(outputStream);
            outputStream.close();
            return new CMSCompressedData(new ContentInfo(CMSObjectIdentifiers.compressedData, new CompressedData(outputCompressor.getAlgorithmIdentifier(), new ContentInfo(cMSTypedData.getContentType(), new BEROctetString(byteArrayOutputStream.toByteArray())))));
        } catch (Exception e) {
            throw new CMSException("exception encoding data.", e);
        }
    }
}
