package org.spongycastle.i18n.filter;

import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.tls.CipherSuite;

public class SQLFilter implements Filter {
    public String doFilter(String input) {
        StringBuffer buf = new StringBuffer(input);
        int i = 0;
        while (i < buf.length()) {
            switch (buf.charAt(i)) {
                case '\n':
                    buf.replace(i, i + 1, "\\n");
                    i++;
                    break;
                case '\r':
                    buf.replace(i, i + 1, "\\r");
                    i++;
                    break;
                case '\"':
                    buf.replace(i, i + 1, "\\\"");
                    i++;
                    break;
                case '\'':
                    buf.replace(i, i + 1, "\\'");
                    i++;
                    break;
                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA /*45*/:
                    buf.replace(i, i + 1, "\\-");
                    i++;
                    break;
                case '/':
                    buf.replace(i, i + 1, "\\/");
                    i++;
                    break;
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                    buf.replace(i, i + 1, "\\;");
                    i++;
                    break;
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 /*61*/:
                    buf.replace(i, i + 1, "\\=");
                    i++;
                    break;
                case EACTags.TAG_LIST /*92*/:
                    buf.replace(i, i + 1, "\\\\");
                    i++;
                    break;
                default:
                    break;
            }
            i++;
        }
        return buf.toString();
    }

    public String doFilterUrl(String input) {
        return doFilter(input);
    }
}
