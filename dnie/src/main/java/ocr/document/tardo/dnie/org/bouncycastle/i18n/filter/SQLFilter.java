package org.bouncycastle.i18n.filter;

import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.tls.CipherSuite;

public class SQLFilter implements Filter {
    public String doFilter(String str) {
        StringBuffer stringBuffer = new StringBuffer(str);
        int i = 0;
        while (i < stringBuffer.length()) {
            switch (stringBuffer.charAt(i)) {
                case '\n':
                    stringBuffer.replace(i, i + 1, "\\n");
                    i++;
                    break;
                case '\r':
                    stringBuffer.replace(i, i + 1, "\\r");
                    i++;
                    break;
                case '\"':
                    stringBuffer.replace(i, i + 1, "\\\"");
                    i++;
                    break;
                case '\'':
                    stringBuffer.replace(i, i + 1, "\\'");
                    i++;
                    break;
                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA /*45*/:
                    stringBuffer.replace(i, i + 1, "\\-");
                    i++;
                    break;
                case '/':
                    stringBuffer.replace(i, i + 1, "\\/");
                    i++;
                    break;
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                    stringBuffer.replace(i, i + 1, "\\;");
                    i++;
                    break;
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 /*61*/:
                    stringBuffer.replace(i, i + 1, "\\=");
                    i++;
                    break;
                case EACTags.TAG_LIST /*92*/:
                    stringBuffer.replace(i, i + 1, "\\\\");
                    i++;
                    break;
                default:
                    break;
            }
            i++;
        }
        return stringBuffer.toString();
    }

    public String doFilterUrl(String str) {
        return doFilter(str);
    }
}
