package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.x501.AttributeTypeAndValue;
import custom.org.apache.harmony.security.x501.AttributeValue;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.tls.CipherSuite;

public class DNParser {
    protected int beg;
    protected char[] chars;
    protected int cur;
    protected byte[] encoded;
    protected int end;
    protected boolean hasQE;
    protected final int length;
    protected int pos;

    public DNParser(String dn) throws IOException {
        this.length = dn.length();
        this.chars = dn.toCharArray();
    }

    protected String nextAT() throws IOException {
        this.hasQE = false;
        while (this.pos < this.length && this.chars[this.pos] == ' ') {
            this.pos++;
        }
        if (this.pos == this.length) {
            return null;
        }
        this.beg = this.pos;
        this.pos++;
        while (this.pos < this.length && this.chars[this.pos] != '=' && this.chars[this.pos] != ' ') {
            this.pos++;
        }
        if (this.pos >= this.length) {
            throw new IOException(Messages.getString("security.192"));
        }
        this.end = this.pos;
        if (this.chars[this.pos] == ' ') {
            while (this.pos < this.length && this.chars[this.pos] != '=' && this.chars[this.pos] == ' ') {
                this.pos++;
            }
            if (this.chars[this.pos] != '=' || this.pos == this.length) {
                throw new IOException(Messages.getString("security.192"));
            }
        }
        this.pos++;
        while (this.pos < this.length && this.chars[this.pos] == ' ') {
            this.pos++;
        }
        if (this.end - this.beg > 4 && this.chars[this.beg + 3] == '.' && ((this.chars[this.beg] == 'O' || this.chars[this.beg] == 'o') && ((this.chars[this.beg + 1] == 'I' || this.chars[this.beg + 1] == 'i') && (this.chars[this.beg + 2] == 'D' || this.chars[this.beg + 2] == 'd')))) {
            this.beg += 4;
        }
        return new String(this.chars, this.beg, this.end - this.beg);
    }

    protected String quotedAV() throws IOException {
        this.pos++;
        this.beg = this.pos;
        this.end = this.beg;
        while (this.pos != this.length) {
            if (this.chars[this.pos] == '\"') {
                this.pos++;
                while (this.pos < this.length && this.chars[this.pos] == ' ') {
                    this.pos++;
                }
                return new String(this.chars, this.beg, this.end - this.beg);
            }
            if (this.chars[this.pos] == '\\') {
                this.chars[this.end] = getEscaped();
            } else {
                this.chars[this.end] = this.chars[this.pos];
            }
            this.pos++;
            this.end++;
        }
        throw new IOException(Messages.getString("security.192"));
    }

    private String hexAV() throws IOException {
        if (this.pos + 4 >= this.length) {
            throw new IOException(Messages.getString("security.192"));
        }
        int hexLen;
        this.beg = this.pos;
        this.pos++;
        while (this.pos != this.length && this.chars[this.pos] != '+' && this.chars[this.pos] != ',' && this.chars[this.pos] != ';') {
            if (this.chars[this.pos] == ' ') {
                this.end = this.pos;
                this.pos++;
                while (this.pos < this.length && this.chars[this.pos] == ' ') {
                    this.pos++;
                }
                hexLen = this.end - this.beg;
                if (hexLen >= 5 || (hexLen & 1) == 0) {
                    throw new IOException(Messages.getString("security.192"));
                }
                this.encoded = new byte[(hexLen / 2)];
                int p = this.beg + 1;
                for (int i = 0; i < this.encoded.length; i++) {
                    this.encoded[i] = (byte) getByte(p);
                    p += 2;
                }
                return new String(this.chars, this.beg, hexLen);
            }
            if (this.chars[this.pos] >= 'A' && this.chars[this.pos] <= 'F') {
                char[] cArr = this.chars;
                int i2 = this.pos;
                cArr[i2] = (char) (cArr[i2] + 32);
            }
            this.pos++;
        }
        this.end = this.pos;
        hexLen = this.end - this.beg;
        if (hexLen >= 5) {
        }
        throw new IOException(Messages.getString("security.192"));
    }

    protected String escapedAV() throws IOException {
        this.beg = this.pos;
        this.end = this.pos;
        while (this.pos < this.length) {
            char[] cArr;
            int i;
            switch (this.chars[this.pos]) {
                case ' ':
                    this.cur = this.end;
                    this.pos++;
                    cArr = this.chars;
                    i = this.end;
                    this.end = i + 1;
                    cArr[i] = ' ';
                    while (this.pos < this.length && this.chars[this.pos] == ' ') {
                        cArr = this.chars;
                        i = this.end;
                        this.end = i + 1;
                        cArr[i] = ' ';
                        this.pos++;
                    }
                    if (this.pos != this.length && this.chars[this.pos] != ',' && this.chars[this.pos] != '+' && this.chars[this.pos] != ';') {
                        break;
                    }
                    return new String(this.chars, this.beg, this.cur - this.beg);
                    break;
                case '+':
                case ',':
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                    return new String(this.chars, this.beg, this.end - this.beg);
                case EACTags.TAG_LIST /*92*/:
                    cArr = this.chars;
                    i = this.end;
                    this.end = i + 1;
                    cArr[i] = getEscaped();
                    this.pos++;
                    break;
                default:
                    cArr = this.chars;
                    i = this.end;
                    this.end = i + 1;
                    cArr[i] = this.chars[this.pos];
                    this.pos++;
                    break;
            }
        }
        return new String(this.chars, this.beg, this.end - this.beg);
    }

    private char getEscaped() throws IOException {
        this.pos++;
        if (this.pos == this.length) {
            throw new IOException(Messages.getString("security.192"));
        }
        switch (this.chars[this.pos]) {
            case ' ':
            case '#':
            case EACTags.APPLICATION_EFFECTIVE_DATE /*37*/:
            case '*':
            case '+':
            case ',':
            case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
            case '<':
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 /*61*/:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 /*62*/:
            case '_':
                break;
            case '\"':
            case EACTags.TAG_LIST /*92*/:
                this.hasQE = true;
                break;
            default:
                return getUTF8();
        }
        return this.chars[this.pos];
    }

    protected char getUTF8() throws IOException {
        int res = getByte(this.pos);
        this.pos++;
        if (res < 128) {
            return (char) res;
        }
        if (res < 192 || res > 247) {
            return '?';
        }
        int count;
        if (res <= 223) {
            count = 1;
            res &= 31;
        } else if (res <= 239) {
            count = 2;
            res &= 15;
        } else {
            count = 3;
            res &= 7;
        }
        for (int i = 0; i < count; i++) {
            this.pos++;
            if (this.pos == this.length || this.chars[this.pos] != '\\') {
                return '?';
            }
            this.pos++;
            int b = getByte(this.pos);
            this.pos++;
            if ((b & 192) != 128) {
                return '?';
            }
            res = (res << 6) + (b & 63);
        }
        return (char) res;
    }

    protected int getByte(int position) throws IOException {
        if (position + 1 >= this.length) {
            throw new IOException(Messages.getString("security.192"));
        }
        int b1 = this.chars[position];
        if (b1 >= 48 && b1 <= 57) {
            b1 -= 48;
        } else if (b1 >= 97 && b1 <= EACTags.CARD_DATA) {
            b1 -= 87;
        } else if (b1 < 65 || b1 > 70) {
            throw new IOException(Messages.getString("security.192"));
        } else {
            b1 -= 55;
        }
        int b2 = this.chars[position + 1];
        if (b2 >= 48 && b2 <= 57) {
            b2 -= 48;
        } else if (b2 >= 97 && b2 <= EACTags.CARD_DATA) {
            b2 -= 87;
        } else if (b2 < 65 || b2 > 70) {
            throw new IOException(Messages.getString("security.192"));
        } else {
            b2 -= 55;
        }
        return (b1 << 4) + b2;
    }

    public List parse() throws IOException {
        List list = new ArrayList();
        String attType = nextAT();
        if (attType != null) {
            List atav = new ArrayList();
            while (this.pos != this.length) {
                switch (this.chars[this.pos]) {
                    case '\"':
                        atav.add(new AttributeTypeAndValue(attType, new AttributeValue(quotedAV(), this.hasQE)));
                        break;
                    case '#':
                        atav.add(new AttributeTypeAndValue(attType, new AttributeValue(hexAV(), this.encoded)));
                        break;
                    case '+':
                    case ',':
                    case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                        atav.add(new AttributeTypeAndValue(attType, new AttributeValue("", false)));
                        break;
                    default:
                        atav.add(new AttributeTypeAndValue(attType, new AttributeValue(escapedAV(), this.hasQE)));
                        break;
                }
                if (this.pos >= this.length) {
                    list.add(0, atav);
                } else {
                    if (this.chars[this.pos] == ',' || this.chars[this.pos] == ';') {
                        list.add(0, atav);
                        atav = new ArrayList();
                    } else if (this.chars[this.pos] != '+') {
                        throw new IOException(Messages.getString("security.192"));
                    }
                    this.pos++;
                    attType = nextAT();
                    if (attType == null) {
                        throw new IOException(Messages.getString("security.192"));
                    }
                }
            }
            atav.add(new AttributeTypeAndValue(attType, new AttributeValue("", false)));
            list.add(0, atav);
        }
        return list;
    }
}
