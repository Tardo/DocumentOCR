package es.gob.jmulticard.card.dnie;

import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PrivateKeyReference;

public final class DniePrivateKeyReference implements PrivateKeyReference {
    private final Dnie dnieCard;
    private final String identifier;
    private final Location keyPath;
    private final String label;

    public DniePrivateKeyReference(Dnie dnieCard, String identifier, Location keyPath, String label) {
        this.dnieCard = dnieCard;
        this.identifier = identifier;
        this.keyPath = keyPath;
        this.label = label;
    }

    public Dnie getDnieCard() {
        return this.dnieCard;
    }

    public String getIdentifier() {
        return this.identifier;
    }

    public Location getKeyPath() {
        return this.keyPath;
    }

    public String getLabel() {
        return this.label;
    }
}
