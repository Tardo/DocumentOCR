package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.DERInteger;

public class SubsequentMessage extends DERInteger {
    public static final SubsequentMessage challengeResp = new SubsequentMessage(1);
    public static final SubsequentMessage encrCert = new SubsequentMessage(0);

    private SubsequentMessage(int value) {
        super(value);
    }

    public static SubsequentMessage valueOf(int value) {
        if (value == 0) {
            return encrCert;
        }
        if (value == 1) {
            return challengeResp;
        }
        throw new IllegalArgumentException("unknown value: " + value);
    }
}