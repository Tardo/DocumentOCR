package org.spongycastle.ocsp;

import java.io.IOException;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.spongycastle.asn1.ocsp.OCSPResponse;
import org.spongycastle.asn1.ocsp.OCSPResponseStatus;
import org.spongycastle.asn1.ocsp.ResponseBytes;

public class OCSPRespGenerator {
    public static final int INTERNAL_ERROR = 2;
    public static final int MALFORMED_REQUEST = 1;
    public static final int SIG_REQUIRED = 5;
    public static final int SUCCESSFUL = 0;
    public static final int TRY_LATER = 3;
    public static final int UNAUTHORIZED = 6;

    public OCSPResp generate(int status, Object response) throws OCSPException {
        if (response == null) {
            return new OCSPResp(new OCSPResponse(new OCSPResponseStatus(status), null));
        }
        if (response instanceof BasicOCSPResp) {
            try {
                return new OCSPResp(new OCSPResponse(new OCSPResponseStatus(status), new ResponseBytes(OCSPObjectIdentifiers.id_pkix_ocsp_basic, new DEROctetString(((BasicOCSPResp) response).getEncoded()))));
            } catch (IOException e) {
                throw new OCSPException("can't encode object.", e);
            }
        }
        throw new OCSPException("unknown response object");
    }
}
