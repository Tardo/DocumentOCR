package de.tsenger.androsmex.mrtd;

public class DG7 {
    private static final short DISPLAYED_PORTRAIT = (short) 24384;
    private static final short DISPLAYED_SIGNATURE = (short) 24387;
    private static final byte HEADER_PORTRAIT_TAG = (byte) 101;
    private static final byte HEADER_SIGNATURE_TAG = (byte) 103;
    private byte[] imageBytes;
    private byte[] rawData;

    public DG7(byte[] rawBytes) {
        this.rawData = (byte[]) rawBytes.clone();
        byte[] signatureDataBlock = ASN1Tools.extractTLV(DISPLAYED_SIGNATURE, this.rawData, 0);
        byte[] imageData = new byte[(signatureDataBlock.length - 5)];
        System.arraycopy(signatureDataBlock, 5, imageData, 0, imageData.length);
        this.imageBytes = (byte[]) imageData.clone();
    }

    public byte[] getBytes() {
        return this.rawData;
    }

    public byte[] getImageBytes() {
        return this.imageBytes;
    }
}
