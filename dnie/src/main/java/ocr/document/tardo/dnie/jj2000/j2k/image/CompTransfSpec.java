package jj2000.j2k.image;

import jj2000.j2k.ModuleSpec;

public class CompTransfSpec extends ModuleSpec {
    public CompTransfSpec(int nt, int nc, byte type) {
        super(nt, nc, type);
    }

    public boolean isCompTransfUsed() {
        if (((Integer) this.def).intValue() != 0) {
            return true;
        }
        if (this.tileDef != null) {
            int t = this.nTiles - 1;
            while (t >= 0) {
                if (this.tileDef[t] != null && ((Integer) this.tileDef[t]).intValue() != 0) {
                    return true;
                }
                t--;
            }
        }
        return false;
    }
}
