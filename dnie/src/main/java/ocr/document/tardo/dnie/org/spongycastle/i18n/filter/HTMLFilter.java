package org.spongycastle.i18n.filter;

import jj2000.j2k.codestream.Markers;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
import org.bouncycastle.crypto.tls.CipherSuite;

public class HTMLFilter implements Filter {
    public String doFilter(String input) {
        StringBuffer buf = new StringBuffer(input);
        int i = 0;
        while (i < buf.length()) {
            switch (buf.charAt(i)) {
                case '\"':
                    buf.replace(i, i + 1, "&#34");
                    break;
                case '#':
                    buf.replace(i, i + 1, "&#35");
                    break;
                case EACTags.APPLICATION_EFFECTIVE_DATE /*37*/:
                    buf.replace(i, i + 1, "&#37");
                    break;
                case Markers.MAX_COMP_BITDEPTH /*38*/:
                    buf.replace(i, i + 1, "&#38");
                    break;
                case '\'':
                    buf.replace(i, i + 1, "&#39");
                    break;
                case JPAKEParticipant.STATE_ROUND_2_VALIDATED /*40*/:
                    buf.replace(i, i + 1, "&#40");
                    break;
                case EACTags.INTERCHANGE_PROFILE /*41*/:
                    buf.replace(i, i + 1, "&#41");
                    break;
                case '+':
                    buf.replace(i, i + 1, "&#43");
                    break;
                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA /*45*/:
                    buf.replace(i, i + 1, "&#45");
                    break;
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                    buf.replace(i, i + 1, "&#59");
                    break;
                case '<':
                    buf.replace(i, i + 1, "&#60");
                    break;
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 /*62*/:
                    buf.replace(i, i + 1, "&#62");
                    break;
                default:
                    i -= 3;
                    break;
            }
            i += 4;
        }
        return buf.toString();
    }

    public String doFilterUrl(String input) {
        return doFilter(input);
    }
}
