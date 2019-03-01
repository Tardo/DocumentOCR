package org.spongycastle.ocsp;

import java.io.IOException;
import java.io.InputStream;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ocsp.BasicOCSPResponse;
import org.spongycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.spongycastle.asn1.ocsp.OCSPResponse;
import org.spongycastle.asn1.ocsp.ResponseBytes;

public class OCSPResp {
    private OCSPResponse resp;

    public OCSPResp(OCSPResponse resp) {
        this.resp = resp;
    }

    public OCSPResp(byte[] resp) throws IOException {
        this(new ASN1InputStream(resp));
    }

    public OCSPResp(InputStream in) throws IOException {
        this(new ASN1InputStream(in));
    }

    private OCSPResp(ASN1InputStream aIn) throws IOException {
        try {
            this.resp = OCSPResponse.getInstance(aIn.readObject());
        } catch (IllegalArgumentException e) {
            throw new IOException("malformed response: " + e.getMessage());
        } catch (ClassCastException e2) {
            throw new IOException("malformed response: " + e2.getMessage());
        }
    }

    public int getStatus() {
        return this.resp.getResponseStatus().getValue().intValue();
    }

    public Object getResponseObject() throws OCSPException {
        ResponseBytes rb = this.resp.getResponseBytes();
        if (rb == null) {
            return null;
        }
        if (!rb.getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
            return rb.getResponse();
        }
        try {
            return new BasicOCSPResp(BasicOCSPResponse.getInstance(ASN1Object.fromByteArray(rb.getResponse().getOctets())));
        } catch (Exception e) {
            throw new OCSPException("problem decoding object: " + e, e);
        }
    }

    public byte[] getEncoded() throws IOException {
        return this.resp.getEncoded();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof OCSPResp)) {
            return false;
        }
        return this.resp.equals(((OCSPResp) o).resp);
    }

    public int hashCode() {
        return this.resp.hashCode();
    }
}
