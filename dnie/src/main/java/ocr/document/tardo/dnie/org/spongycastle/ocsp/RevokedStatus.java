package org.spongycastle.ocsp;

import java.text.ParseException;
import java.util.Date;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.ocsp.RevokedInfo;
import org.spongycastle.asn1.x509.CRLReason;

public class RevokedStatus implements CertificateStatus {
    RevokedInfo info;

    public RevokedStatus(RevokedInfo info) {
        this.info = info;
    }

    public RevokedStatus(Date revocationDate, int reason) {
        this.info = new RevokedInfo(new DERGeneralizedTime(revocationDate), new CRLReason(reason));
    }

    public Date getRevocationTime() {
        try {
            return this.info.getRevocationTime().getDate();
        } catch (ParseException e) {
            throw new IllegalStateException("ParseException:" + e.getMessage());
        }
    }

    public boolean hasRevocationReason() {
        return this.info.getRevocationReason() != null;
    }

    public int getRevocationReason() {
        if (this.info.getRevocationReason() != null) {
            return this.info.getRevocationReason().getValue().intValue();
        }
        throw new IllegalStateException("attempt to get a reason where none is available");
    }
}
