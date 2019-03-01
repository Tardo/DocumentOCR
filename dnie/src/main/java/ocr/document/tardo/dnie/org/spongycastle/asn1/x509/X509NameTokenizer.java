package org.spongycastle.asn1.x509;

public class X509NameTokenizer {
    private StringBuffer buf;
    private int index;
    private char seperator;
    private String value;

    public X509NameTokenizer(String oid) {
        this(oid, ',');
    }

    public X509NameTokenizer(String oid, char seperator) {
        this.buf = new StringBuffer();
        this.value = oid;
        this.index = -1;
        this.seperator = seperator;
    }

    public boolean hasMoreTokens() {
        return this.index != this.value.length();
    }

    public String nextToken() {
        if (this.index == this.value.length()) {
            return null;
        }
        int end = this.index + 1;
        boolean quoted = false;
        boolean escaped = false;
        this.buf.setLength(0);
        while (end != this.value.length()) {
            char c = this.value.charAt(end);
            if (c == '\"') {
                if (escaped) {
                    this.buf.append(c);
                } else {
                    quoted = !quoted;
                }
                escaped = false;
            } else if (escaped || quoted) {
                if (c == '#' && this.buf.charAt(this.buf.length() - 1) == '=') {
                    this.buf.append('\\');
                } else if (c == '+' && this.seperator != '+') {
                    this.buf.append('\\');
                }
                this.buf.append(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == this.seperator) {
                break;
            } else {
                this.buf.append(c);
            }
            end++;
        }
        this.index = end;
        return this.buf.toString().trim();
    }
}
