package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.DEREnumerated;

public class CRLReason extends DEREnumerated {
    public static final int AA_COMPROMISE = 10;
    public static final int AFFILIATION_CHANGED = 3;
    public static final int CA_COMPROMISE = 2;
    public static final int CERTIFICATE_HOLD = 6;
    public static final int CESSATION_OF_OPERATION = 5;
    public static final int KEY_COMPROMISE = 1;
    public static final int PRIVILEGE_WITHDRAWN = 9;
    public static final int REMOVE_FROM_CRL = 8;
    public static final int SUPERSEDED = 4;
    public static final int UNSPECIFIED = 0;
    public static final int aACompromise = 10;
    public static final int affiliationChanged = 3;
    public static final int cACompromise = 2;
    public static final int certificateHold = 6;
    public static final int cessationOfOperation = 5;
    public static final int keyCompromise = 1;
    public static final int privilegeWithdrawn = 9;
    private static final String[] reasonString = new String[]{"unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "unknown", "removeFromCRL", "privilegeWithdrawn", "aACompromise"};
    public static final int removeFromCRL = 8;
    public static final int superseded = 4;
    public static final int unspecified = 0;

    public CRLReason(int reason) {
        super(reason);
    }

    public CRLReason(DEREnumerated reason) {
        super(reason.getValue().intValue());
    }

    public String toString() {
        String str;
        int reason = getValue().intValue();
        if (reason < 0 || reason > 10) {
            str = "invalid";
        } else {
            str = reasonString[reason];
        }
        return "CRLReason: " + str;
    }
}
