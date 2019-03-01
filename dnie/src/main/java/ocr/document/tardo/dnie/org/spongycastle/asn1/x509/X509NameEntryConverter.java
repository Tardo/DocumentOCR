package org.spongycastle.asn1.x509;

import java.io.IOException;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.util.Strings;

public abstract class X509NameEntryConverter {
    public abstract DERObject getConvertedValue(DERObjectIdentifier dERObjectIdentifier, String str);

    protected DERObject convertHexEncoded(String str, int off) throws IOException {
        str = Strings.toLowerCase(str);
        byte[] data = new byte[((str.length() - off) / 2)];
        for (int index = 0; index != data.length; index++) {
            char left = str.charAt((index * 2) + off);
            char right = str.charAt(((index * 2) + off) + 1);
            if (left < 'a') {
                data[index] = (byte) ((left - 48) << 4);
            } else {
                data[index] = (byte) (((left - 97) + 10) << 4);
            }
            if (right < 'a') {
                data[index] = (byte) (data[index] | ((byte) (right - 48)));
            } else {
                data[index] = (byte) (data[index] | ((byte) ((right - 97) + 10)));
            }
        }
        return new ASN1InputStream(data).readObject();
    }

    protected boolean canBePrintable(String str) {
        return DERPrintableString.isPrintableString(str);
    }
}
