package jj2000.j2k.entropy;

public interface StdEntropyCoderOptions {
    public static final int FIRST_BYPASS_PASS_IDX = 10;
    public static final int MAX_CB_AREA = 4096;
    public static final int MAX_CB_DIM = 1024;
    public static final int MIN_CB_DIM = 4;
    public static final int NUM_EMPTY_PASSES_IN_MS_BP = 2;
    public static final int NUM_NON_BYPASS_MS_BP = 4;
    public static final int NUM_PASSES = 3;
    public static final int OPT_BYPASS = 1;
    public static final int OPT_PRED_TERM = 16;
    public static final int OPT_RESET_MQ = 2;
    public static final int OPT_SEG_SYMBOLS = 32;
    public static final int OPT_TERM_PASS = 4;
    public static final int OPT_VERT_STR_CAUSAL = 8;
    public static final int STRIPE_HEIGHT = 4;
}
