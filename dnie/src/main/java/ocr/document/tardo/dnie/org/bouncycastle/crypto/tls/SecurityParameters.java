package org.bouncycastle.crypto.tls;

public class SecurityParameters {
    byte[] clientRandom = null;
    short compressionAlgorithm = (short) -1;
    int entity = -1;
    byte[] masterSecret = null;
    int prfAlgorithm = -1;
    byte[] serverRandom = null;
    int verifyDataLength = -1;

    public byte[] getClientRandom() {
        return this.clientRandom;
    }

    public short getCompressionAlgorithm() {
        return this.compressionAlgorithm;
    }

    public int getEntity() {
        return this.entity;
    }

    public byte[] getMasterSecret() {
        return this.masterSecret;
    }

    public int getPrfAlgorithm() {
        return this.prfAlgorithm;
    }

    public byte[] getServerRandom() {
        return this.serverRandom;
    }

    public int getVerifyDataLength() {
        return this.verifyDataLength;
    }
}
