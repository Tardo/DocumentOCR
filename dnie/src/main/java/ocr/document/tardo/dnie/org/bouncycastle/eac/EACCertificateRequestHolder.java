package org.bouncycastle.eac;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.asn1.eac.CVCertificateRequest;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.eac.operator.EACSignatureVerifier;

public class EACCertificateRequestHolder {
    private CVCertificateRequest request;

    public EACCertificateRequestHolder(CVCertificateRequest cVCertificateRequest) {
        this.request = cVCertificateRequest;
    }

    public EACCertificateRequestHolder(byte[] bArr) throws IOException {
        this(parseBytes(bArr));
    }

    private static CVCertificateRequest parseBytes(byte[] bArr) throws IOException {
        try {
            return CVCertificateRequest.getInstance(bArr);
        } catch (Throwable e) {
            throw new EACIOException("malformed data: " + e.getMessage(), e);
        } catch (Throwable e2) {
            throw new EACIOException("malformed data: " + e2.getMessage(), e2);
        } catch (Throwable e22) {
            if (e22.getCause() instanceof IOException) {
                throw ((IOException) e22.getCause());
            }
            throw new EACIOException("malformed data: " + e22.getMessage(), e22);
        }
    }

    public PublicKeyDataObject getPublicKeyDataObject() {
        return this.request.getPublicKey();
    }

    public boolean isInnerSignatureValid(EACSignatureVerifier eACSignatureVerifier) throws EACException {
        try {
            OutputStream outputStream = eACSignatureVerifier.getOutputStream();
            outputStream.write(this.request.getCertificateBody().getEncoded("DER"));
            outputStream.close();
            return eACSignatureVerifier.verify(this.request.getInnerSignature());
        } catch (Throwable e) {
            throw new EACException("unable to process signature: " + e.getMessage(), e);
        }
    }

    public CVCertificateRequest toASN1Structure() {
        return this.request;
    }
}
