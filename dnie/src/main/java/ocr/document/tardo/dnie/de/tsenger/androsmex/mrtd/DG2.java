package de.tsenger.androsmex.mrtd;

import android.graphics.Bitmap;

public class DG2 {
    private static final short BIOMETRIC_DATA_TAG = (short) 24366;
    private static final byte BIOMETRIC_HEADER_TEMPLATE_TAG = (byte) -95;
    private static final short BIOMETRIC_INFO_GROUP_TAG = (short) 32609;
    private static final short BIOMETRIC_INFO_TAG = (short) 32608;
    private static final byte FACIAL_BIOMETRIC_DATA_GROUP_TAG = (byte) 117;
    private static final byte FORMAT_OWNER_TAG = (byte) -121;
    private static final byte FORMAT_TYPE_TAG = (byte) -120;
    private Bitmap image;
    private byte[] imageBytes;
    private byte[] rawData;

    public DG2(byte[] rawBytes) {
        this.rawData = (byte[]) rawBytes.clone();
        byte[] bioDataBlock = ASN1Tools.extractTLV(BIOMETRIC_DATA_TAG, ASN1Tools.extractTLV(BIOMETRIC_INFO_TAG, ASN1Tools.extractTLV(BIOMETRIC_INFO_GROUP_TAG, rawBytes, 0), 0), 0);
        byte[] imageData = new byte[(bioDataBlock.length - 51)];
        System.arraycopy(bioDataBlock, 51, imageData, 0, imageData.length);
        this.imageBytes = (byte[]) imageData.clone();
    }

    public byte[] getBytes() {
        return this.rawData;
    }

    public byte[] getImageBytes() {
        return this.imageBytes;
    }
}
