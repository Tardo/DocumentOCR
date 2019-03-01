package jj2000.j2k.codestream.reader;

import java.io.IOException;
import jj2000.j2k.util.ArrayUtil;

public class TagTreeDecoder {
    /* renamed from: h */
    protected int f28h;
    protected int lvls;
    protected int[][] treeS;
    protected int[][] treeV;
    /* renamed from: w */
    protected int f29w;

    public TagTreeDecoder(int h, int w) {
        if (w < 0 || h < 0) {
            throw new IllegalArgumentException();
        }
        this.f29w = w;
        this.f28h = h;
        if (w != 0 && h != 0) {
            this.lvls = 1;
            while (true) {
                if (h == 1 && w == 1) {
                    break;
                }
                w = (w + 1) >> 1;
                h = (h + 1) >> 1;
                this.lvls++;
            }
        } else {
            this.lvls = 0;
        }
        this.treeV = new int[this.lvls][];
        this.treeS = new int[this.lvls][];
        w = this.f29w;
        h = this.f28h;
        for (int i = 0; i < this.lvls; i++) {
            this.treeV[i] = new int[(h * w)];
            ArrayUtil.intArraySet(this.treeV[i], Integer.MAX_VALUE);
            this.treeS[i] = new int[(h * w)];
            w = (w + 1) >> 1;
            h = (h + 1) >> 1;
        }
    }

    public final int getWidth() {
        return this.f29w;
    }

    public final int getHeight() {
        return this.f28h;
    }

    public int update(int m, int n, int t, PktHeaderBitReader in) throws IOException {
        if (m >= this.f28h || n >= this.f29w || t < 0) {
            throw new IllegalArgumentException();
        }
        int k = this.lvls - 1;
        int tmin = this.treeS[k][0];
        int idx = ((m >> k) * (((this.f29w + (1 << k)) - 1) >> k)) + (n >> k);
        while (true) {
            int ts;
            int ts2 = this.treeS[k][idx];
            int tv = this.treeV[k][idx];
            if (ts2 < tmin) {
                ts = tmin;
            } else {
                ts = ts2;
            }
            while (t > ts) {
                if (tv < ts) {
                    ts2 = t;
                    break;
                } else if (in.readBit() == 0) {
                    ts++;
                } else {
                    tv = ts;
                    ts++;
                }
            }
            ts2 = ts;
            this.treeS[k][idx] = ts2;
            this.treeV[k][idx] = tv;
            if (k <= 0) {
                return tv;
            }
            if (ts2 < tv) {
                tmin = ts2;
            } else {
                tmin = tv;
            }
            k--;
            idx = ((m >> k) * (((this.f29w + (1 << k)) - 1) >> k)) + (n >> k);
        }
    }

    public int getValue(int m, int n) {
        if (m < this.f28h && n < this.f29w) {
            return this.treeV[0][(this.f29w * m) + n];
        }
        throw new IllegalArgumentException();
    }
}
