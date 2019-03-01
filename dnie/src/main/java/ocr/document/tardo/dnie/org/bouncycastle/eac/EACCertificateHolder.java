package org.bouncycastle.eac;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.asn1.eac.CVCertificate;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.eac.operator.EACSignatureVerifier;

public class EACCertificateHolder {
    private CVCertificate cvCertificate;

    public EACCertificateHolder(CVCertificate cVCertificate) {
        this.cvCertificate = cVCertificate;
    }

    public EACCertificateHolder(byte[] bArr) throws IOException {
        this(parseBytes(bArr));
    }

    private static CVCertificate parseBytes(byte[] bArr) throws IOException {
        try {
            return CVCertificate.getInstance(bArr);
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
        return this.cvCertificate.getBody().getPublicKey();
    }

    public boolean isSignatureValid(EACSignatureVerifier eACSignatureVerifier) throws EACException {
        try {
            OutputStream outputStream = eACSignatureVerifier.getOutputStream();
            outputStream.write(this.cvCertificate.getBody().getEncoded("DER"));
            outputStream.close();
            return eACSignatureVerifier.verify(this.cvCertificate.getSignature());
        } catch (Throwable e) {
            throw new EACException("unable to process signature: " + e.getMessage(), e);
        }
    }

    public CVCertificate toASN1Structure() {
        return this.cvCertificate;
    }
}
