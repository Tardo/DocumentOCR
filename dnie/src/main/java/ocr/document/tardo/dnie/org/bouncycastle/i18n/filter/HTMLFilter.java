package org.bouncycastle.i18n.filter;

import jj2000.j2k.codestream.Markers;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
import org.bouncycastle.crypto.tls.CipherSuite;

public class HTMLFilter implements Filter {
    public String doFilter(String str) {
        StringBuffer stringBuffer = new StringBuffer(str);
        int i = 0;
        while (i < stringBuffer.length()) {
            switch (stringBuffer.charAt(i)) {
                case '\"':
                    stringBuffer.replace(i, i + 1, "&#34");
                    break;
                case '#':
                    stringBuffer.replace(i, i + 1, "&#35");
                    break;
                case EACTags.APPLICATION_EFFECTIVE_DATE /*37*/:
                    stringBuffer.replace(i, i + 1, "&#37");
                    break;
                case Markers.MAX_COMP_BITDEPTH /*38*/:
                    stringBuffer.replace(i, i + 1, "&#38");
                    break;
                case '\'':
                    stringBuffer.replace(i, i + 1, "&#39");
                    break;
                case JPAKEParticipant.STATE_ROUND_2_VALIDATED /*40*/:
                    stringBuffer.replace(i, i + 1, "&#40");
                    break;
                case EACTags.INTERCHANGE_PROFILE /*41*/:
                    stringBuffer.replace(i, i + 1, "&#41");
                    break;
                case '+':
                    stringBuffer.replace(i, i + 1, "&#43");
                    break;
                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA /*45*/:
                    stringBuffer.replace(i, i + 1, "&#45");
                    break;
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                    stringBuffer.replace(i, i + 1, "&#59");
                    break;
                case '<':
                    stringBuffer.replace(i, i + 1, "&#60");
                    break;
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 /*62*/:
                    stringBuffer.replace(i, i + 1, "&#62");
                    break;
                default:
                    i -= 3;
                    break;
            }
            i += 4;
        }
        return stringBuffer.toString();
    }

    public String doFilterUrl(String str) {
        return doFilter(str);
    }
}
