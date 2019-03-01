package de.tsenger.androsmex.mrtd;

public class EF_COM {
    private byte[] rawData;
    private byte[] tlvAppTemplate = null;
    private byte[] tlvLdsVersion = null;
    private byte[] tlvTagList = null;
    private byte[] tlvUnicodeVersion = null;

    public EF_COM(byte[] rawBytes) {
        this.rawData = (byte[]) rawBytes.clone();
        this.tlvAppTemplate = ASN1Tools.extractTag((byte) 96, rawBytes, 0);
        this.tlvLdsVersion = ASN1Tools.extractTLV((short) 24321, this.tlvAppTemplate, 0);
        this.tlvUnicodeVersion = ASN1Tools.extractTLV((short) 24374, this.tlvAppTemplate, 4);
        this.tlvTagList = ASN1Tools.extractTag((byte) 92, this.tlvAppTemplate, 10);
    }

    public byte[] getBytes() {
        return this.rawData;
    }

    public String getLDSVersion() {
        return JSmexTools.toChar(this.tlvLdsVersion[3]) + "" + JSmexTools.toChar(this.tlvLdsVersion[4]) + "." + JSmexTools.toChar(this.tlvLdsVersion[5]) + "" + JSmexTools.toChar(this.tlvLdsVersion[6]);
    }

    public String getUnicodeVersion() {
        return JSmexTools.toChar(this.tlvUnicodeVersion[3]) + "" + JSmexTools.toChar(this.tlvUnicodeVersion[4]) + "." + JSmexTools.toChar(this.tlvUnicodeVersion[5]) + "" + JSmexTools.toChar(this.tlvUnicodeVersion[6]) + "." + JSmexTools.toChar(this.tlvUnicodeVersion[7]) + "" + JSmexTools.toChar(this.tlvUnicodeVersion[8]);
    }

    public byte[] getTagList() {
        byte[] tagList = new byte[this.tlvTagList[1]];
        System.arraycopy(this.tlvTagList, 2, tagList, 0, tagList.length);
        return tagList;
    }
}
