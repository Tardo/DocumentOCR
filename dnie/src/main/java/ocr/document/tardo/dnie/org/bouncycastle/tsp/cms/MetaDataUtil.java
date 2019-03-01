package org.bouncycastle.tsp.cms;

import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.MetaData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DigestCalculator;

class MetaDataUtil {
    private final MetaData metaData;

    MetaDataUtil(MetaData metaData) {
        this.metaData = metaData;
    }

    private String convertString(ASN1String aSN1String) {
        return aSN1String != null ? aSN1String.toString() : null;
    }

    String getFileName() {
        return this.metaData != null ? convertString(this.metaData.getFileName()) : null;
    }

    String getMediaType() {
        return this.metaData != null ? convertString(this.metaData.getMediaType()) : null;
    }

    Attributes getOtherMetaData() {
        return this.metaData != null ? this.metaData.getOtherMetaData() : null;
    }

    void initialiseMessageImprintDigestCalculator(DigestCalculator digestCalculator) throws CMSException {
        if (this.metaData != null && this.metaData.isHashProtected()) {
            try {
                digestCalculator.getOutputStream().write(this.metaData.getEncoded("DER"));
            } catch (Exception e) {
                throw new CMSException("unable to initialise calculator from metaData: " + e.getMessage(), e);
            }
        }
    }
}
