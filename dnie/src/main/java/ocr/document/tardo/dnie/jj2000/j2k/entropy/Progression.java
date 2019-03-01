package jj2000.j2k.entropy;

import jj2000.j2k.codestream.ProgressionType;

public class Progression implements ProgressionType {
    public int ce;
    public int cs;
    public int lye;
    public int re;
    public int rs;
    public int type;

    public Progression(int type, int cs, int ce, int rs, int re, int lye) {
        this.type = type;
        this.cs = cs;
        this.ce = ce;
        this.rs = rs;
        this.re = re;
        this.lye = lye;
    }

    public String toString() {
        String str = "type= ";
        switch (this.type) {
            case 0:
                str = str + "layer, ";
                break;
            case 1:
                str = str + "res, ";
                break;
            case 2:
                str = str + "res-pos, ";
                break;
            case 3:
                str = str + "pos-comp, ";
                break;
            case 4:
                str = str + "pos-comp, ";
                break;
            default:
                throw new Error("Unknown progression type");
        }
        return ((str + "comp.: " + this.cs + "-" + this.ce + ", ") + "res.: " + this.rs + "-" + this.re + ", ") + "layer: up to " + this.lye;
    }
}
