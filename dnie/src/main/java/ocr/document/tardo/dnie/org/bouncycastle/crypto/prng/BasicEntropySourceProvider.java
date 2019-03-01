package org.bouncycastle.crypto.prng;

import java.security.SecureRandom;

public class BasicEntropySourceProvider implements EntropySourceProvider {
    private final boolean _predictionResistant;
    private final SecureRandom _sr;

    public BasicEntropySourceProvider(SecureRandom secureRandom, boolean z) {
        this._sr = secureRandom;
        this._predictionResistant = z;
    }

    public EntropySource get(final int i) {
        return new EntropySource() {
            public int entropySize() {
                return i;
            }

            public byte[] getEntropy() {
                return BasicEntropySourceProvider.this._sr.generateSeed((i + 7) / 8);
            }

            public boolean isPredictionResistant() {
                return BasicEntropySourceProvider.this._predictionResistant;
            }
        };
    }
}
