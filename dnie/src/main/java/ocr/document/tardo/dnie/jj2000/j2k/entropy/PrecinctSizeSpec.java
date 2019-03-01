package jj2000.j2k.entropy;

import java.util.NoSuchElementException;
import java.util.StringTokenizer;
import java.util.Vector;
import jj2000.j2k.IntegerSpec;
import jj2000.j2k.ModuleSpec;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.util.MathUtil;
import jj2000.j2k.util.ParameterList;
import org.bouncycastle.asn1.eac.EACTags;

public class PrecinctSizeSpec extends ModuleSpec {
    private static final String optName = "Cpp";
    private IntegerSpec dls;

    public PrecinctSizeSpec(int nt, int nc, byte type, IntegerSpec dls) {
        super(nt, nc, type);
        this.dls = dls;
    }

    public PrecinctSizeSpec(int nt, int nc, byte type, BlkImgDataSrc imgsrc, IntegerSpec dls, ParameterList pl) {
        super(nt, nc, type);
        this.dls = dls;
        boolean wasReadingPrecinctSize = false;
        String param = pl.getParameter(optName);
        Vector[] tmpv = new Vector[2];
        tmpv[0] = new Vector();
        tmpv[0].addElement(new Integer(65535));
        tmpv[1] = new Vector();
        tmpv[1].addElement(new Integer(65535));
        setDefault(tmpv);
        if (param != null) {
            StringTokenizer stk = new StringTokenizer(param);
            byte curSpecType = (byte) 0;
            boolean[] tileSpec = null;
            boolean[] compSpec = null;
            boolean endOfParamList = false;
            String word = null;
            while (true) {
                if ((stk.hasMoreTokens() || wasReadingPrecinctSize) && !endOfParamList) {
                    Vector[] v = new Vector[2];
                    if (!wasReadingPrecinctSize) {
                        word = stk.nextToken();
                    }
                    wasReadingPrecinctSize = false;
                    switch (word.charAt(0)) {
                        case EACTags.WRAPPER /*99*/:
                            compSpec = ModuleSpec.parseIdx(word, this.nComp);
                            if (curSpecType != (byte) 2) {
                                curSpecType = (byte) 1;
                                break;
                            } else {
                                curSpecType = (byte) 3;
                                break;
                            }
                        case 't':
                            tileSpec = ModuleSpec.parseIdx(word, this.nTiles);
                            if (curSpecType != (byte) 1) {
                                curSpecType = (byte) 2;
                                break;
                            } else {
                                curSpecType = (byte) 3;
                                break;
                            }
                        default:
                            if (Character.isDigit(word.charAt(0))) {
                                int ti;
                                int ci;
                                v[0] = new Vector();
                                v[1] = new Vector();
                                do {
                                    Integer w = new Integer(word);
                                    try {
                                        word = stk.nextToken();
                                        Integer h = new Integer(word);
                                        if (w.intValue() == (1 << MathUtil.log2(w.intValue())) && h.intValue() == (1 << MathUtil.log2(h.intValue()))) {
                                            v[0].addElement(w);
                                            v[1].addElement(h);
                                            if (!stk.hasMoreTokens()) {
                                                if (curSpecType == (byte) 0) {
                                                    setDefault(v);
                                                } else if (curSpecType == (byte) 2) {
                                                    for (ti = tileSpec.length - 1; ti >= 0; ti--) {
                                                        if (tileSpec[ti]) {
                                                            setTileDef(ti, v);
                                                        }
                                                    }
                                                } else if (curSpecType == (byte) 1) {
                                                    for (ci = compSpec.length - 1; ci >= 0; ci--) {
                                                        if (compSpec[ci]) {
                                                            setCompDef(ci, v);
                                                        }
                                                    }
                                                } else {
                                                    for (ti = tileSpec.length - 1; ti >= 0; ti--) {
                                                        ci = compSpec.length - 1;
                                                        while (ci >= 0) {
                                                            if (tileSpec[ti] && compSpec[ci]) {
                                                                setTileCompVal(ti, ci, v);
                                                            }
                                                            ci--;
                                                        }
                                                    }
                                                }
                                                endOfParamList = true;
                                                break;
                                            }
                                            word = stk.nextToken();
                                        } else {
                                            throw new IllegalArgumentException("Precinct dimensions must be powers of 2");
                                        }
                                    } catch (NoSuchElementException e) {
                                        throw new IllegalArgumentException("'Cpp' option : could not parse the precinct's width");
                                    } catch (NumberFormatException e2) {
                                        throw new IllegalArgumentException("'Cpp' option : the argument '" + word + "' could not be parsed.");
                                    }
                                } while (Character.isDigit(word.charAt(0)));
                                wasReadingPrecinctSize = true;
                                if (curSpecType == (byte) 0) {
                                    setDefault(v);
                                } else if (curSpecType == (byte) 2) {
                                    for (ti = tileSpec.length - 1; ti >= 0; ti--) {
                                        if (tileSpec[ti]) {
                                            setTileDef(ti, v);
                                        }
                                    }
                                } else if (curSpecType == (byte) 1) {
                                    for (ci = compSpec.length - 1; ci >= 0; ci--) {
                                        if (compSpec[ci]) {
                                            setCompDef(ci, v);
                                        }
                                    }
                                } else {
                                    for (ti = tileSpec.length - 1; ti >= 0; ti--) {
                                        ci = compSpec.length - 1;
                                        while (ci >= 0) {
                                            if (tileSpec[ti] && compSpec[ci]) {
                                                setTileCompVal(ti, ci, v);
                                            }
                                            ci--;
                                        }
                                    }
                                }
                                curSpecType = (byte) 0;
                                tileSpec = null;
                                compSpec = null;
                                break;
                            }
                            throw new IllegalArgumentException("Bad construction for parameter: " + word);
                            break;
                    }
                }
                return;
            }
        }
    }

    public int getPPX(int t, int c, int rl) {
        boolean tileSpecified;
        int mrl;
        Vector[] v;
        boolean compSpecified = true;
        if (t != -1) {
            tileSpecified = true;
        } else {
            tileSpecified = false;
        }
        if (c == -1) {
            compSpecified = false;
        }
        if (tileSpecified && compSpecified) {
            mrl = ((Integer) this.dls.getTileCompVal(t, c)).intValue();
            v = (Vector[]) getTileCompVal(t, c);
        } else if (tileSpecified && !compSpecified) {
            mrl = ((Integer) this.dls.getTileDef(t)).intValue();
            v = (Vector[]) getTileDef(t);
        } else if (tileSpecified || !compSpecified) {
            mrl = ((Integer) this.dls.getDefault()).intValue();
            v = (Vector[]) getDefault();
        } else {
            mrl = ((Integer) this.dls.getCompDef(c)).intValue();
            v = (Vector[]) getCompDef(c);
        }
        int idx = mrl - rl;
        if (v[0].size() > idx) {
            return ((Integer) v[0].elementAt(idx)).intValue();
        }
        return ((Integer) v[0].elementAt(v[0].size() - 1)).intValue();
    }

    public int getPPY(int t, int c, int rl) {
        boolean tileSpecified;
        int mrl;
        Vector[] v;
        boolean compSpecified = false;
        if (t != -1) {
            tileSpecified = true;
        } else {
            tileSpecified = false;
        }
        if (c != -1) {
            compSpecified = true;
        }
        if (tileSpecified && compSpecified) {
            mrl = ((Integer) this.dls.getTileCompVal(t, c)).intValue();
            v = (Vector[]) getTileCompVal(t, c);
        } else if (tileSpecified && !compSpecified) {
            mrl = ((Integer) this.dls.getTileDef(t)).intValue();
            v = (Vector[]) getTileDef(t);
        } else if (tileSpecified || !compSpecified) {
            mrl = ((Integer) this.dls.getDefault()).intValue();
            v = (Vector[]) getDefault();
        } else {
            mrl = ((Integer) this.dls.getCompDef(c)).intValue();
            v = (Vector[]) getCompDef(c);
        }
        int idx = mrl - rl;
        if (v[1].size() > idx) {
            return ((Integer) v[1].elementAt(idx)).intValue();
        }
        return ((Integer) v[1].elementAt(v[1].size() - 1)).intValue();
    }
}
