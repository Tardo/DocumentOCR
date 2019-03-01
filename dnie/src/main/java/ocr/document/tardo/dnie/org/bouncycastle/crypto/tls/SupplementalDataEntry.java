package org.bouncycastle.crypto.tls;

public class SupplementalDataEntry {
    private byte[] data;
    private int supp_data_type;

    public SupplementalDataEntry(int i, byte[] bArr) {
        this.supp_data_type = i;
        this.data = bArr;
    }

    public byte[] getData() {
        return this.data;
    }

    public int getDataType() {
        return this.supp_data_type;
    }
}
