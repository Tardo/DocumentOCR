package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1String;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBMPString;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERUTF8String;
import org.spongycastle.asn1.DERVisibleString;

public class DisplayText extends ASN1Encodable implements ASN1Choice {
    public static final int CONTENT_TYPE_BMPSTRING = 1;
    public static final int CONTENT_TYPE_IA5STRING = 0;
    public static final int CONTENT_TYPE_UTF8STRING = 2;
    public static final int CONTENT_TYPE_VISIBLESTRING = 3;
    public static final int DISPLAY_TEXT_MAXIMUM_SIZE = 200;
    int contentType;
    ASN1String contents;

    public DisplayText(int type, String text) {
        if (text.length() > 200) {
            text = text.substring(0, 200);
        }
        this.contentType = type;
        switch (type) {
            case 0:
                this.contents = new DERIA5String(text);
                return;
            case 1:
                this.contents = new DERBMPString(text);
                return;
            case 2:
                this.contents = new DERUTF8String(text);
                return;
            case 3:
                this.contents = new DERVisibleString(text);
                return;
            default:
                this.contents = new DERUTF8String(text);
                return;
        }
    }

    public DisplayText(String text) {
        if (text.length() > 200) {
            text = text.substring(0, 200);
        }
        this.contentType = 2;
        this.contents = new DERUTF8String(text);
    }

    private DisplayText(ASN1String de) {
        this.contents = de;
    }

    public static DisplayText getInstance(Object obj) {
        if (obj instanceof ASN1String) {
            return new DisplayText((ASN1String) obj);
        }
        if (obj instanceof DisplayText) {
            return (DisplayText) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DisplayText getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    public DERObject toASN1Object() {
        return (DERObject) this.contents;
    }

    public String getString() {
        return this.contents.getString();
    }
}
