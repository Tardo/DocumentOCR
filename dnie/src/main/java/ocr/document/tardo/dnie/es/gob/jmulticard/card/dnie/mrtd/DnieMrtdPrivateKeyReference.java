package es.gob.jmulticard.card.dnie.mrtd;

import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PrivateKeyReference;

public final class DnieMrtdPrivateKeyReference implements PrivateKeyReference {
    private final DnieMrtd dnieCard;
    private final String identifier;
    private final Location keyPath;
    private final String label;

    public DnieMrtdPrivateKeyReference(DnieMrtd dnieCard, String identifier, Location keyPath, String label) {
        this.dnieCard = dnieCard;
        this.identifier = identifier;
        this.keyPath = keyPath;
        this.label = label;
    }

    public DnieMrtd getDnieCard() {
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
