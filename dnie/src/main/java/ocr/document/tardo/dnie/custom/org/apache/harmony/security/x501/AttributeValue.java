package custom.org.apache.harmony.security.x501;

import custom.org.apache.harmony.security.asn1.ASN1StringType;
import custom.org.apache.harmony.security.asn1.DerInputStream;
import custom.org.apache.harmony.security.x509.Utils;
import java.io.IOException;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.tls.CipherSuite;

public class AttributeValue {
    public byte[] bytes;
    public byte[] encoded;
    public String escapedString;
    public boolean hasQE;
    private String hexString;
    public String rawString;
    private int tag = -1;
    public final boolean wasEncoded = false;

    public AttributeValue(String parsedString, boolean hasQorE) {
        this.hasQE = hasQorE;
        this.rawString = parsedString;
        this.escapedString = makeEscaped(this.rawString);
    }

    public AttributeValue(String hexString, byte[] encoded) {
        this.hexString = hexString;
        this.encoded = encoded;
        try {
            DerInputStream in = new DerInputStream(encoded);
            this.tag = in.tag;
            if (DirectoryString.ASN1.checkTag(this.tag)) {
                this.rawString = (String) DirectoryString.ASN1.decode(in);
                this.escapedString = makeEscaped(this.rawString);
                return;
            }
            this.rawString = hexString;
            this.escapedString = hexString;
        } catch (IOException e) {
            IllegalArgumentException iae = new IllegalArgumentException();
            iae.initCause(e);
            throw iae;
        }
    }

    public AttributeValue(String rawString, byte[] encoded, int tag) {
        this.encoded = encoded;
        this.tag = tag;
        if (rawString == null) {
            this.rawString = getHexString();
            this.escapedString = this.hexString;
            return;
        }
        this.rawString = rawString;
        this.escapedString = makeEscaped(rawString);
    }

    public int getTag() {
        if (this.tag == -1) {
            if (Utils.isPrintableString(this.rawString)) {
                this.tag = ASN1StringType.PRINTABLESTRING.id;
            } else {
                this.tag = ASN1StringType.UTF8STRING.id;
            }
        }
        return this.tag;
    }

    public String getHexString() {
        if (this.hexString == null) {
            if (!this.wasEncoded) {
                if (Utils.isPrintableString(this.rawString)) {
                    this.encoded = ASN1StringType.PRINTABLESTRING.encode(this.rawString);
                } else {
                    this.encoded = ASN1StringType.UTF8STRING.encode(this.rawString);
                }
            }
            StringBuilder buf = new StringBuilder((this.encoded.length * 2) + 1);
            buf.append('#');
            for (int i = 0; i < this.encoded.length; i++) {
                int c = (this.encoded[i] >> 4) & 15;
                if (c < 10) {
                    buf.append((char) (c + 48));
                } else {
                    buf.append((char) (c + 87));
                }
                c = this.encoded[i] & 15;
                if (c < 10) {
                    buf.append((char) (c + 48));
                } else {
                    buf.append((char) (c + 87));
                }
            }
            this.hexString = buf.toString();
        }
        return this.hexString;
    }

    public void appendQEString(StringBuffer buf) {
        buf.append('\"');
        if (this.hasQE) {
            for (int i = 0; i < this.rawString.length(); i++) {
                char c = this.rawString.charAt(i);
                if (c == '\"' || c == '\\') {
                    buf.append('\\');
                }
                buf.append(c);
            }
        } else {
            buf.append(this.rawString);
        }
        buf.append('\"');
    }

    private String makeEscaped(String name) {
        int length = name.length();
        if (length == 0) {
            return name;
        }
        StringBuilder buf = new StringBuilder(length * 2);
        int index = 0;
        while (index < length) {
            char ch = name.charAt(index);
            switch (ch) {
                case ' ':
                    if (index == 0 || index == length - 1) {
                        buf.append('\\');
                    }
                    buf.append(' ');
                    continue;
                case '\"':
                case EACTags.TAG_LIST /*92*/:
                    this.hasQE = true;
                    break;
                case '#':
                case '+':
                case ',':
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                case '<':
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 /*61*/:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 /*62*/:
                    break;
            }
            buf.append('\\');
            buf.append(ch);
            continue;
            index++;
        }
        return buf.toString();
    }

    public String makeCanonical() {
        int length = this.rawString.length();
        if (length == 0) {
            return this.rawString;
        }
        int bufLength;
        StringBuilder buf = new StringBuilder(length * 2);
        int index = 0;
        if (this.rawString.charAt(0) == '#') {
            buf.append('\\');
            buf.append('#');
            index = 0 + 1;
        }
        while (index < length) {
            char ch = this.rawString.charAt(index);
            switch (ch) {
                case ' ':
                    bufLength = buf.length();
                    if (!(bufLength == 0 || buf.charAt(bufLength - 1) == ' ')) {
                        buf.append(' ');
                        break;
                    }
                case '\"':
                case '+':
                case ',':
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                case '<':
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 /*62*/:
                case EACTags.TAG_LIST /*92*/:
                    buf.append('\\');
                    break;
            }
            buf.append(ch);
            index++;
        }
        bufLength = buf.length() - 1;
        while (bufLength > -1 && buf.charAt(bufLength) == ' ') {
            bufLength--;
        }
        buf.setLength(bufLength + 1);
        return buf.toString();
    }
}
