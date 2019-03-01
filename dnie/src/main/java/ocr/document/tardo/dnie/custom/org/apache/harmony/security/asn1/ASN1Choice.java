package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.TreeMap;

public abstract class ASN1Choice extends ASN1Type {
    private final int[][] identifiers;
    public final ASN1Type[] type;

    public abstract int getIndex(Object obj);

    public abstract Object getObjectToEncode(Object obj);

    public ASN1Choice(ASN1Type[] type) {
        super(0);
        if (type.length == 0) {
            throw new IllegalArgumentException(Messages.getString("security.10E", getClass().getName()));
        }
        TreeMap map = new TreeMap();
        for (int index = 0; index < type.length; index++) {
            ASN1Type t = type[index];
            if (t instanceof ASN1Any) {
                throw new IllegalArgumentException(Messages.getString("security.10F", getClass().getName()));
            }
            if (t instanceof ASN1Choice) {
                int[][] choiceToAdd = ((ASN1Choice) t).identifiers;
                for (int addIdentifier : choiceToAdd[0]) {
                    addIdentifier(map, addIdentifier, index);
                }
            } else {
                if (t.checkTag(t.id)) {
                    addIdentifier(map, t.id, index);
                }
                if (t.checkTag(t.constrId)) {
                    addIdentifier(map, t.constrId, index);
                }
            }
        }
        int size = map.size();
        this.identifiers = (int[][]) Array.newInstance(Integer.TYPE, new int[]{2, size});
        Iterator it = map.entrySet().iterator();
        for (int i = 0; i < size; i++) {
            Entry entry = (Entry) it.next();
            this.identifiers[0][i] = ((BigInteger) entry.getKey()).intValue();
            this.identifiers[1][i] = ((BigInteger) entry.getValue()).intValue();
        }
        this.type = type;
    }

    private void addIdentifier(TreeMap map, int identifier, int index) {
        if (map.put(BigInteger.valueOf((long) identifier), BigInteger.valueOf((long) index)) != null) {
            throw new IllegalArgumentException(Messages.getString("security.10F", getClass().getName()));
        }
    }

    public final boolean checkTag(int identifier) {
        return Arrays.binarySearch(this.identifiers[0], identifier) >= 0;
    }

    public Object decode(BerInputStream in) throws IOException {
        int index = Arrays.binarySearch(this.identifiers[0], in.tag);
        if (index < 0) {
            throw new ASN1Exception(Messages.getString("security.110", getClass().getName()));
        }
        index = this.identifiers[1][index];
        in.content = this.type[index].decode(in);
        in.choiceIndex = index;
        if (in.isVerify) {
            return null;
        }
        return getDecodedObject(in);
    }

    public void encodeASN(BerOutputStream out) {
        encodeContent(out);
    }

    public final void encodeContent(BerOutputStream out) {
        out.encodeChoice(this);
    }

    public final void setEncodingContent(BerOutputStream out) {
        out.getChoiceLength(this);
    }
}
