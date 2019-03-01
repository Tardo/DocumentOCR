package org.spongycastle.asn1;

import java.io.IOException;
import org.spongycastle.util.Arrays;

public class DERUnknownTag extends DERObject {
    private byte[] data;
    private boolean isConstructed;
    private int tag;

    public DERUnknownTag(int tag, byte[] data) {
        this(false, tag, data);
    }

    public DERUnknownTag(boolean isConstructed, int tag, byte[] data) {
        this.isConstructed = isConstructed;
        this.tag = tag;
        this.data = data;
    }

    public boolean isConstructed() {
        return this.isConstructed;
    }

    public int getTag() {
        return this.tag;
    }

    public byte[] getData() {
        return this.data;
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(this.isConstructed ? 32 : 0, this.tag, this.data);
    }

    public boolean equals(Object o) {
        if (!(o instanceof DERUnknownTag)) {
            return false;
        }
        DERUnknownTag other = (DERUnknownTag) o;
        if (this.isConstructed == other.isConstructed && this.tag == other.tag && Arrays.areEqual(this.data, other.data)) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return ((this.isConstructed ? -1 : 0) ^ this.tag) ^ Arrays.hashCode(this.data);
    }
}
