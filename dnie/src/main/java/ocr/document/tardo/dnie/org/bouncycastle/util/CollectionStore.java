package org.bouncycastle.util;

import java.util.ArrayList;
import java.util.Collection;

public class CollectionStore implements Store {
    private Collection _local;

    public CollectionStore(Collection collection) {
        this._local = new ArrayList(collection);
    }

    public Collection getMatches(Selector selector) {
        if (selector == null) {
            return new ArrayList(this._local);
        }
        Collection arrayList = new ArrayList();
        for (Object next : this._local) {
            if (selector.match(next)) {
                arrayList.add(next);
            }
        }
        return arrayList;
    }
}
