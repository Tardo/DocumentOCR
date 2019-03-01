package org.bouncycastle.dvcs;

import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

public class SignedDVCSMessageGenerator {
    private final CMSSignedDataGenerator signedDataGen;

    public SignedDVCSMessageGenerator(CMSSignedDataGenerator cMSSignedDataGenerator) {
        this.signedDataGen = cMSSignedDataGenerator;
    }

    public CMSSignedData build(DVCSMessage dVCSMessage) throws DVCSException {
        try {
            return this.signedDataGen.generate(new CMSProcessableByteArray(dVCSMessage.getContentType(), dVCSMessage.getContent().toASN1Primitive().getEncoded("DER")), true);
        } catch (Throwable e) {
            throw new DVCSException("Could not sign DVCS request", e);
        } catch (Throwable e2) {
            throw new DVCSException("Could not encode DVCS request", e2);
        }
    }
}
