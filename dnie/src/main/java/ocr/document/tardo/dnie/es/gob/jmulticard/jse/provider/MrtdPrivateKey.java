package es.gob.jmulticard.jse.provider;

import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.dnie.mrtd.DnieMrtd;
import es.gob.jmulticard.card.dnie.mrtd.DnieMrtdPrivateKeyReference;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

public final class MrtdPrivateKey implements RSAPrivateKey {
    private static final long serialVersionUID = 4403051294889801855L;
    private final DnieMrtd dnieMrtd;
    private final String id;
    private final String name;
    private final Location path;

    public String toString() {
        return this.name;
    }

    MrtdPrivateKey(DnieMrtdPrivateKeyReference keyReference) {
        this.dnieMrtd = keyReference.getDnieCard();
        this.id = keyReference.getIdentifier();
        this.path = keyReference.getKeyPath();
        this.name = keyReference.getLabel();
    }

    CryptoCard getCryptoCard() {
        return this.dnieMrtd;
    }

    public String getAlgorithm() {
        return "RSA";
    }

    public byte[] getEncoded() {
        return null;
    }

    public String getFormat() {
        return null;
    }

    public BigInteger getModulus() {
        throw new UnsupportedOperationException();
    }

    public BigInteger getPrivateExponent() {
        throw new UnsupportedOperationException();
    }

    String getId() {
        return this.id;
    }

    Location getPath() {
        return this.path;
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        throw new NotSerializableException();
    }
}
