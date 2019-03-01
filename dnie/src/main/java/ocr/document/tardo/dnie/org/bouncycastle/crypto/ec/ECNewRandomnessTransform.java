package org.bouncycastle.crypto.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECPoint;

public class ECNewRandomnessTransform implements ECPairTransform {
    private ECPublicKeyParameters key;
    private SecureRandom random;

    public void init(CipherParameters cipherParameters) {
        if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            if (parametersWithRandom.getParameters() instanceof ECPublicKeyParameters) {
                this.key = (ECPublicKeyParameters) parametersWithRandom.getParameters();
                this.random = parametersWithRandom.getRandom();
                return;
            }
            throw new IllegalArgumentException("ECPublicKeyParameters are required for new randomness transform.");
        } else if (cipherParameters instanceof ECPublicKeyParameters) {
            this.key = (ECPublicKeyParameters) cipherParameters;
            this.random = new SecureRandom();
        } else {
            throw new IllegalArgumentException("ECPublicKeyParameters are required for new randomness transform.");
        }
    }

    public ECPair transform(ECPair eCPair) {
        if (this.key == null) {
            throw new IllegalStateException("ECNewRandomnessTransform not initialised");
        }
        BigInteger generateK = ECUtil.generateK(this.key.getParameters().getN(), this.random);
        ECPoint multiply = this.key.getParameters().getG().multiply(generateK);
        return new ECPair(eCPair.getX().add(multiply), this.key.getQ().multiply(generateK).add(eCPair.getY()));
    }
}
