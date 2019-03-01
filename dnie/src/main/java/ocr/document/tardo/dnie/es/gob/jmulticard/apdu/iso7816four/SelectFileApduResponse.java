package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.Apdu;
import es.gob.jmulticard.apdu.ResponseApdu;

public final class SelectFileApduResponse extends ResponseApdu {
    private byte[] dfName = null;
    private byte[] fileId = null;
    private byte[] fileLength = null;

    public SelectFileApduResponse(Apdu apduResponse) {
        super(apduResponse.getBytes());
        decode();
    }

    private void decode() {
        if (isOk() && getData().length - 2 == getData()[1]) {
            int propInformationIndex = 2;
            if (getData()[2] == (byte) -124) {
                propInformationIndex = 2 + 1;
                int nameLength = getData()[propInformationIndex];
                this.dfName = getBytesFromData(propInformationIndex + 1, nameLength);
                propInformationIndex = nameLength + 4;
            }
            if (getData()[propInformationIndex] == (byte) -123 && getData()[propInformationIndex + 1] == (byte) 10) {
                this.fileId = getBytesFromData(propInformationIndex + 3, 2);
                this.fileLength = getBytesFromData(propInformationIndex + 5, 2);
            }
        }
    }

    private byte[] getBytesFromData(int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(getData(), offset, result, 0, length);
        return result;
    }

    byte[] getDfName() {
        byte[] out = new byte[this.dfName.length];
        System.arraycopy(this.dfName, 0, out, 0, this.dfName.length);
        return out;
    }

    byte[] getFileId() {
        byte[] out = new byte[this.fileId.length];
        System.arraycopy(this.fileId, 0, out, 0, this.fileId.length);
        return out;
    }

    public int getFileLength() {
        return ((this.fileLength[0] & 255) << 8) | (this.fileLength[1] & 255);
    }

    public boolean isOk() {
        getBytesFromData(getData().length - 2, 2);
        if (super.isOk() && getData()[0] == (byte) 111 && getData().length > 2) {
            return true;
        }
        return false;
    }
}
