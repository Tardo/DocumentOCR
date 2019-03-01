package org.bouncycastle.crypto.tls;

class DTLSEpoch {
    private final TlsCipher cipher;
    private final int epoch;
    private final DTLSReplayWindow replayWindow = new DTLSReplayWindow();
    private long sequence_number = 0;

    DTLSEpoch(int i, TlsCipher tlsCipher) {
        if (i < 0) {
            throw new IllegalArgumentException("'epoch' must be >= 0");
        } else if (tlsCipher == null) {
            throw new IllegalArgumentException("'cipher' cannot be null");
        } else {
            this.epoch = i;
            this.cipher = tlsCipher;
        }
    }

    long allocateSequenceNumber() {
        long j = this.sequence_number;
        this.sequence_number = 1 + j;
        return j;
    }

    TlsCipher getCipher() {
        return this.cipher;
    }

    int getEpoch() {
        return this.epoch;
    }

    DTLSReplayWindow getReplayWindow() {
        return this.replayWindow;
    }

    long getSequence_number() {
        return this.sequence_number;
    }
}
