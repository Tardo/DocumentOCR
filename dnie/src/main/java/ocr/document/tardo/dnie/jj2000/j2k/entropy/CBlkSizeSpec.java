package jj2000.j2k.entropy;

import java.util.NoSuchElementException;
import java.util.StringTokenizer;
import jj2000.j2k.ModuleSpec;
import jj2000.j2k.util.MathUtil;
import jj2000.j2k.util.ParameterList;
import org.bouncycastle.asn1.eac.EACTags;

public class CBlkSizeSpec extends ModuleSpec {
    private static final String optName = "Cblksiz";
    private int maxCBlkHeight = 0;
    private int maxCBlkWidth = 0;

    public CBlkSizeSpec(int nt, int nc, byte type) {
        super(nt, nc, type);
    }

    public CBlkSizeSpec(int nt, int nc, byte type, ParameterList pl) {
        super(nt, nc, type);
        boolean firstVal = true;
        StringTokenizer stk = new StringTokenizer(pl.getParameter(optName));
        byte curSpecType = (byte) 0;
        boolean[] tileSpec = null;
        boolean[] compSpec = null;
        while (stk.hasMoreTokens()) {
            String word = stk.nextToken();
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
                        Integer[] dim = new Integer[2];
                        try {
                            dim[0] = new Integer(word);
                            if (dim[0].intValue() > 1024) {
                                throw new IllegalArgumentException("'Cblksiz' option : the code-block's width cannot be greater than 1024");
                            } else if (dim[0].intValue() < 4) {
                                throw new IllegalArgumentException("'Cblksiz' option : the code-block's width cannot be less than 4");
                            } else if (dim[0].intValue() != (1 << MathUtil.log2(dim[0].intValue()))) {
                                throw new IllegalArgumentException("'Cblksiz' option : the code-block's width must be a power of 2");
                            } else {
                                try {
                                    try {
                                        dim[1] = new Integer(stk.nextToken());
                                        if (dim[1].intValue() <= 1024) {
                                            if (dim[1].intValue() >= 4) {
                                                if (dim[1].intValue() == (1 << MathUtil.log2(dim[1].intValue()))) {
                                                    if (dim[0].intValue() * dim[1].intValue() <= 4096) {
                                                        if (dim[0].intValue() > this.maxCBlkWidth) {
                                                            this.maxCBlkWidth = dim[0].intValue();
                                                        }
                                                        if (dim[1].intValue() > this.maxCBlkHeight) {
                                                            this.maxCBlkHeight = dim[1].intValue();
                                                        }
                                                        if (firstVal) {
                                                            setDefault(dim);
                                                            firstVal = false;
                                                        }
                                                        int ci;
                                                        int ti;
                                                        switch (curSpecType) {
                                                            case (byte) 0:
                                                                setDefault(dim);
                                                                break;
                                                            case (byte) 1:
                                                                for (ci = compSpec.length - 1; ci >= 0; ci--) {
                                                                    if (compSpec[ci]) {
                                                                        setCompDef(ci, dim);
                                                                    }
                                                                }
                                                                break;
                                                            case (byte) 2:
                                                                for (ti = tileSpec.length - 1; ti >= 0; ti--) {
                                                                    if (tileSpec[ti]) {
                                                                        setTileDef(ti, dim);
                                                                    }
                                                                }
                                                                break;
                                                            default:
                                                                for (ti = tileSpec.length - 1; ti >= 0; ti--) {
                                                                    ci = compSpec.length - 1;
                                                                    while (ci >= 0) {
                                                                        if (tileSpec[ti] && compSpec[ci]) {
                                                                            setTileCompVal(ti, ci, dim);
                                                                        }
                                                                        ci--;
                                                                    }
                                                                }
                                                                break;
                                                        }
                                                    }
                                                    throw new IllegalArgumentException("'Cblksiz' option : The code-block's area (i.e. width*height) cannot be greater than 4096");
                                                }
                                                throw new IllegalArgumentException("'Cblksiz' option : the code-block's height must be a power of 2");
                                            }
                                            throw new IllegalArgumentException("'Cblksiz' option : the code-block's height cannot be less than 4");
                                        }
                                        throw new IllegalArgumentException("'Cblksiz' option : the code-block's height cannot be greater than 1024");
                                    } catch (NumberFormatException e) {
                                        throw new IllegalArgumentException("'Cblksiz' option : the code-block's height could not be parsed.");
                                    }
                                } catch (NoSuchElementException e2) {
                                    throw new IllegalArgumentException("'Cblksiz' option : could not parse the code-block's height");
                                }
                            }
                        } catch (NumberFormatException e3) {
                            throw new IllegalArgumentException("'Cblksiz' option : the code-block's width could not be parsed.");
                        }
                    }
                    throw new IllegalArgumentException("Bad construction for parameter: " + word);
            }
        }
    }

    public int getMaxCBlkWidth() {
        return this.maxCBlkWidth;
    }

    public int getMaxCBlkHeight() {
        return this.maxCBlkHeight;
    }

    public int getCBlkWidth(byte type, int t, int c) {
        Integer[] dim = null;
        switch (type) {
            case (byte) 0:
                dim = (Integer[]) getDefault();
                break;
            case (byte) 1:
                dim = (Integer[]) getCompDef(c);
                break;
            case (byte) 2:
                dim = (Integer[]) getTileDef(t);
                break;
            case (byte) 3:
                dim = (Integer[]) getTileCompVal(t, c);
                break;
        }
        return dim[0].intValue();
    }

    public int getCBlkHeight(byte type, int t, int c) {
        Integer[] dim = null;
        switch (type) {
            case (byte) 0:
                dim = (Integer[]) getDefault();
                break;
            case (byte) 1:
                dim = (Integer[]) getCompDef(c);
                break;
            case (byte) 2:
                dim = (Integer[]) getTileDef(t);
                break;
            case (byte) 3:
                dim = (Integer[]) getTileCompVal(t, c);
                break;
        }
        return dim[1].intValue();
    }

    public void setDefault(Object value) {
        super.setDefault(value);
        storeHighestDims((Integer[]) value);
    }

    public void setTileDef(int t, Object value) {
        super.setTileDef(t, value);
        storeHighestDims((Integer[]) value);
    }

    public void setCompDef(int c, Object value) {
        super.setCompDef(c, value);
        storeHighestDims((Integer[]) value);
    }

    public void setTileCompVal(int t, int c, Object value) {
        super.setTileCompVal(t, c, value);
        storeHighestDims((Integer[]) value);
    }

    private void storeHighestDims(Integer[] dim) {
        if (dim[0].intValue() > this.maxCBlkWidth) {
            this.maxCBlkWidth = dim[0].intValue();
        }
        if (dim[1].intValue() > this.maxCBlkHeight) {
            this.maxCBlkHeight = dim[1].intValue();
        }
    }
}
