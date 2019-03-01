package es.gob.jmulticard.jse.provider;

import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DniePrivateKeyReference;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

public final class DniePrivateKey implements RSAPrivateKey {
    private static final long serialVersionUID = 4403051294889801855L;
    private final Dnie dnie;
    private final String id;
    private final String name;
    private final Location path;

    public String toString() {
        return this.name;
    }

    DniePrivateKey(DniePrivateKeyReference keyReference) {
        this.dnie = keyReference.getDnieCard();
        this.id = keyReference.getIdentifier();
        this.path = keyReference.getKeyPath();
        this.name = keyReference.getLabel();
    }

    CryptoCard getCryptoCard() {
        return this.dnie;
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
