package jj2000.j2k.image;

public class Coord {
    /* renamed from: x */
    public int f36x;
    /* renamed from: y */
    public int f37y;

    public Coord(int x, int y) {
        this.f36x = x;
        this.f37y = y;
    }

    public Coord(Coord c) {
        this.f36x = c.f36x;
        this.f37y = c.f37y;
    }

    public String toString() {
        return "(" + this.f36x + "," + this.f37y + ")";
    }
}
