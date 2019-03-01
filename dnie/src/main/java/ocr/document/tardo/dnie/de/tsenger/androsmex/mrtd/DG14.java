package de.tsenger.androsmex.mrtd;

public class DG14 {
    private byte[] rawData;

    public DG14(byte[] rawBytes) {
        this.rawData = (byte[]) rawBytes.clone();
    }

    public byte[] getBytes() {
        return this.rawData;
    }
}
