package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.x501.AttributeType;
import java.lang.reflect.Array;
import java.util.Arrays;

public class InformationObjectSet {
    private final int capacity;
    private final Entry[][] pool;

    private static class Entry {
        public Object object;
        public int[] oid;

        public Entry(int[] oid, Object object) {
            this.oid = oid;
            this.object = object;
        }
    }

    public InformationObjectSet() {
        this(64, 10);
    }

    public InformationObjectSet(int capacity, int size) {
        this.capacity = capacity;
        this.pool = (Entry[][]) Array.newInstance(Entry.class, new int[]{capacity, size});
    }

    public void put(AttributeType at) {
        put(at.oid.getOid(), at);
    }

    public void put(int[] oid, Object object) {
        Entry[] list = this.pool[hashIntArray(oid) % this.capacity];
        int i = 0;
        while (list[i] != null) {
            if (Arrays.equals(oid, list[i].oid)) {
                throw new Error();
            }
            i++;
        }
        if (i == this.capacity - 1) {
            throw new Error();
        }
        list[i] = new Entry(oid, object);
    }

    public Object get(int[] oid) {
        Entry[] list = this.pool[hashIntArray(oid) % this.capacity];
        for (int i = 0; list[i] != null; i++) {
            if (Arrays.equals(oid, list[i].oid)) {
                return list[i].object;
            }
        }
        return null;
    }

    private int hashIntArray(int[] array) {
        int intHash = 0;
        int i = 0;
        while (i < array.length && i < 4) {
            intHash += array[i] << (i * 8);
            i++;
        }
        return Integer.MAX_VALUE & intHash;
    }
}
