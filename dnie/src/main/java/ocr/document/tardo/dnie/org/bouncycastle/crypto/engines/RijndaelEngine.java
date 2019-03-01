package org.bouncycastle.crypto.engines;

import custom.org.apache.harmony.xnet.provider.jsse.Handshake;
import java.lang.reflect.Array;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.tls.CipherSuite;

public class RijndaelEngine implements BlockCipher {
    private static final int MAXKC = 64;
    private static final int MAXROUNDS = 14;
    /* renamed from: S */
    private static final byte[] f246S = new byte[]{(byte) 99, (byte) 124, (byte) 119, (byte) 123, (byte) -14, (byte) 107, (byte) 111, (byte) -59, (byte) 48, (byte) 1, (byte) 103, (byte) 43, (byte) -2, (byte) -41, (byte) -85, (byte) 118, (byte) -54, (byte) -126, (byte) -55, (byte) 125, (byte) -6, (byte) 89, (byte) 71, (byte) -16, (byte) -83, (byte) -44, (byte) -94, (byte) -81, (byte) -100, (byte) -92, (byte) 114, (byte) -64, (byte) -73, (byte) -3, (byte) -109, (byte) 38, (byte) 54, (byte) 63, (byte) -9, (byte) -52, (byte) 52, (byte) -91, (byte) -27, (byte) -15, (byte) 113, (byte) -40, (byte) 49, (byte) 21, (byte) 4, (byte) -57, (byte) 35, (byte) -61, (byte) 24, (byte) -106, (byte) 5, (byte) -102, (byte) 7, (byte) 18, Byte.MIN_VALUE, (byte) -30, (byte) -21, (byte) 39, (byte) -78, (byte) 117, (byte) 9, (byte) -125, (byte) 44, (byte) 26, (byte) 27, (byte) 110, (byte) 90, (byte) -96, (byte) 82, (byte) 59, (byte) -42, (byte) -77, (byte) 41, (byte) -29, (byte) 47, (byte) -124, (byte) 83, (byte) -47, (byte) 0, (byte) -19, (byte) 32, (byte) -4, (byte) -79, (byte) 91, (byte) 106, (byte) -53, (byte) -66, (byte) 57, (byte) 74, (byte) 76, (byte) 88, (byte) -49, (byte) -48, (byte) -17, (byte) -86, (byte) -5, (byte) 67, (byte) 77, (byte) 51, (byte) -123, (byte) 69, (byte) -7, (byte) 2, Byte.MAX_VALUE, (byte) 80, (byte) 60, (byte) -97, (byte) -88, (byte) 81, (byte) -93, (byte) 64, (byte) -113, (byte) -110, (byte) -99, (byte) 56, (byte) -11, (byte) -68, (byte) -74, (byte) -38, (byte) 33, (byte) 16, (byte) -1, (byte) -13, (byte) -46, (byte) -51, (byte) 12, (byte) 19, (byte) -20, (byte) 95, (byte) -105, (byte) 68, (byte) 23, (byte) -60, (byte) -89, (byte) 126, (byte) 61, (byte) 100, (byte) 93, (byte) 25, (byte) 115, (byte) 96, (byte) -127, (byte) 79, (byte) -36, (byte) 34, (byte) 42, (byte) -112, (byte) -120, (byte) 70, (byte) -18, (byte) -72, Handshake.FINISHED, (byte) -34, (byte) 94, (byte) 11, (byte) -37, (byte) -32, (byte) 50, (byte) 58, (byte) 10, (byte) 73, (byte) 6, (byte) 36, (byte) 92, (byte) -62, (byte) -45, (byte) -84, (byte) 98, (byte) -111, (byte) -107, (byte) -28, (byte) 121, (byte) -25, (byte) -56, (byte) 55, (byte) 109, (byte) -115, (byte) -43, (byte) 78, (byte) -87, (byte) 108, (byte) 86, (byte) -12, (byte) -22, (byte) 101, (byte) 122, (byte) -82, (byte) 8, (byte) -70, (byte) 120, (byte) 37, (byte) 46, (byte) 28, (byte) -90, (byte) -76, (byte) -58, (byte) -24, (byte) -35, (byte) 116, (byte) 31, (byte) 75, (byte) -67, (byte) -117, (byte) -118, (byte) 112, (byte) 62, (byte) -75, (byte) 102, (byte) 72, (byte) 3, (byte) -10, Handshake.SERVER_HELLO_DONE, (byte) 97, (byte) 53, (byte) 87, (byte) -71, (byte) -122, (byte) -63, (byte) 29, (byte) -98, (byte) -31, (byte) -8, (byte) -104, (byte) 17, (byte) 105, (byte) -39, (byte) -114, (byte) -108, (byte) -101, (byte) 30, (byte) -121, (byte) -23, (byte) -50, (byte) 85, (byte) 40, (byte) -33, (byte) -116, (byte) -95, (byte) -119, (byte) 13, (byte) -65, (byte) -26, (byte) 66, (byte) 104, (byte) 65, (byte) -103, (byte) 45, Handshake.CERTIFICATE_VERIFY, (byte) -80, (byte) 84, (byte) -69, (byte) 22};
    private static final byte[] Si = new byte[]{(byte) 82, (byte) 9, (byte) 106, (byte) -43, (byte) 48, (byte) 54, (byte) -91, (byte) 56, (byte) -65, (byte) 64, (byte) -93, (byte) -98, (byte) -127, (byte) -13, (byte) -41, (byte) -5, (byte) 124, (byte) -29, (byte) 57, (byte) -126, (byte) -101, (byte) 47, (byte) -1, (byte) -121, (byte) 52, (byte) -114, (byte) 67, (byte) 68, (byte) -60, (byte) -34, (byte) -23, (byte) -53, (byte) 84, (byte) 123, (byte) -108, (byte) 50, (byte) -90, (byte) -62, (byte) 35, (byte) 61, (byte) -18, (byte) 76, (byte) -107, (byte) 11, (byte) 66, (byte) -6, (byte) -61, (byte) 78, (byte) 8, (byte) 46, (byte) -95, (byte) 102, (byte) 40, (byte) -39, (byte) 36, (byte) -78, (byte) 118, (byte) 91, (byte) -94, (byte) 73, (byte) 109, (byte) -117, (byte) -47, (byte) 37, (byte) 114, (byte) -8, (byte) -10, (byte) 100, (byte) -122, (byte) 104, (byte) -104, (byte) 22, (byte) -44, (byte) -92, (byte) 92, (byte) -52, (byte) 93, (byte) 101, (byte) -74, (byte) -110, (byte) 108, (byte) 112, (byte) 72, (byte) 80, (byte) -3, (byte) -19, (byte) -71, (byte) -38, (byte) 94, (byte) 21, (byte) 70, (byte) 87, (byte) -89, (byte) -115, (byte) -99, (byte) -124, (byte) -112, (byte) -40, (byte) -85, (byte) 0, (byte) -116, (byte) -68, (byte) -45, (byte) 10, (byte) -9, (byte) -28, (byte) 88, (byte) 5, (byte) -72, (byte) -77, (byte) 69, (byte) 6, (byte) -48, (byte) 44, (byte) 30, (byte) -113, (byte) -54, (byte) 63, Handshake.CERTIFICATE_VERIFY, (byte) 2, (byte) -63, (byte) -81, (byte) -67, (byte) 3, (byte) 1, (byte) 19, (byte) -118, (byte) 107, (byte) 58, (byte) -111, (byte) 17, (byte) 65, (byte) 79, (byte) 103, (byte) -36, (byte) -22, (byte) -105, (byte) -14, (byte) -49, (byte) -50, (byte) -16, (byte) -76, (byte) -26, (byte) 115, (byte) -106, (byte) -84, (byte) 116, (byte) 34, (byte) -25, (byte) -83, (byte) 53, (byte) -123, (byte) -30, (byte) -7, (byte) 55, (byte) -24, (byte) 28, (byte) 117, (byte) -33, (byte) 110, (byte) 71, (byte) -15, (byte) 26, (byte) 113, (byte) 29, (byte) 41, (byte) -59, (byte) -119, (byte) 111, (byte) -73, (byte) 98, Handshake.SERVER_HELLO_DONE, (byte) -86, (byte) 24, (byte) -66, (byte) 27, (byte) -4, (byte) 86, (byte) 62, (byte) 75, (byte) -58, (byte) -46, (byte) 121, (byte) 32, (byte) -102, (byte) -37, (byte) -64, (byte) -2, (byte) 120, (byte) -51, (byte) 90, (byte) -12, (byte) 31, (byte) -35, (byte) -88, (byte) 51, (byte) -120, (byte) 7, (byte) -57, (byte) 49, (byte) -79, (byte) 18, (byte) 16, (byte) 89, (byte) 39, Byte.MIN_VALUE, (byte) -20, (byte) 95, (byte) 96, (byte) 81, Byte.MAX_VALUE, (byte) -87, (byte) 25, (byte) -75, (byte) 74, (byte) 13, (byte) 45, (byte) -27, (byte) 122, (byte) -97, (byte) -109, (byte) -55, (byte) -100, (byte) -17, (byte) -96, (byte) -32, (byte) 59, (byte) 77, (byte) -82, (byte) 42, (byte) -11, (byte) -80, (byte) -56, (byte) -21, (byte) -69, (byte) 60, (byte) -125, (byte) 83, (byte) -103, (byte) 97, (byte) 23, (byte) 43, (byte) 4, (byte) 126, (byte) -70, (byte) 119, (byte) -42, (byte) 38, (byte) -31, (byte) 105, Handshake.FINISHED, (byte) 99, (byte) 85, (byte) 33, (byte) 12, (byte) 125};
    private static final byte[] aLogtable = new byte[]{(byte) 0, (byte) 3, (byte) 5, Handshake.CERTIFICATE_VERIFY, (byte) 17, (byte) 51, (byte) 85, (byte) -1, (byte) 26, (byte) 46, (byte) 114, (byte) -106, (byte) -95, (byte) -8, (byte) 19, (byte) 53, (byte) 95, (byte) -31, (byte) 56, (byte) 72, (byte) -40, (byte) 115, (byte) -107, (byte) -92, (byte) -9, (byte) 2, (byte) 6, (byte) 10, (byte) 30, (byte) 34, (byte) 102, (byte) -86, (byte) -27, (byte) 52, (byte) 92, (byte) -28, (byte) 55, (byte) 89, (byte) -21, (byte) 38, (byte) 106, (byte) -66, (byte) -39, (byte) 112, (byte) -112, (byte) -85, (byte) -26, (byte) 49, (byte) 83, (byte) -11, (byte) 4, (byte) 12, Handshake.FINISHED, (byte) 60, (byte) 68, (byte) -52, (byte) 79, (byte) -47, (byte) 104, (byte) -72, (byte) -45, (byte) 110, (byte) -78, (byte) -51, (byte) 76, (byte) -44, (byte) 103, (byte) -87, (byte) -32, (byte) 59, (byte) 77, (byte) -41, (byte) 98, (byte) -90, (byte) -15, (byte) 8, (byte) 24, (byte) 40, (byte) 120, (byte) -120, (byte) -125, (byte) -98, (byte) -71, (byte) -48, (byte) 107, (byte) -67, (byte) -36, Byte.MAX_VALUE, (byte) -127, (byte) -104, (byte) -77, (byte) -50, (byte) 73, (byte) -37, (byte) 118, (byte) -102, (byte) -75, (byte) -60, (byte) 87, (byte) -7, (byte) 16, (byte) 48, (byte) 80, (byte) -16, (byte) 11, (byte) 29, (byte) 39, (byte) 105, (byte) -69, (byte) -42, (byte) 97, (byte) -93, (byte) -2, (byte) 25, (byte) 43, (byte) 125, (byte) -121, (byte) -110, (byte) -83, (byte) -20, (byte) 47, (byte) 113, (byte) -109, (byte) -82, (byte) -23, (byte) 32, (byte) 96, (byte) -96, (byte) -5, (byte) 22, (byte) 58, (byte) 78, (byte) -46, (byte) 109, (byte) -73, (byte) -62, (byte) 93, (byte) -25, (byte) 50, (byte) 86, (byte) -6, (byte) 21, (byte) 63, (byte) 65, (byte) -61, (byte) 94, (byte) -30, (byte) 61, (byte) 71, (byte) -55, (byte) 64, (byte) -64, (byte) 91, (byte) -19, (byte) 44, (byte) 116, (byte) -100, (byte) -65, (byte) -38, (byte) 117, (byte) -97, (byte) -70, (byte) -43, (byte) 100, (byte) -84, (byte) -17, (byte) 42, (byte) 126, (byte) -126, (byte) -99, (byte) -68, (byte) -33, (byte) 122, (byte) -114, (byte) -119, Byte.MIN_VALUE, (byte) -101, (byte) -74, (byte) -63, (byte) 88, (byte) -24, (byte) 35, (byte) 101, (byte) -81, (byte) -22, (byte) 37, (byte) 111, (byte) -79, (byte) -56, (byte) 67, (byte) -59, (byte) 84, (byte) -4, (byte) 31, (byte) 33, (byte) 99, (byte) -91, (byte) -12, (byte) 7, (byte) 9, (byte) 27, (byte) 45, (byte) 119, (byte) -103, (byte) -80, (byte) -53, (byte) 70, (byte) -54, (byte) 69, (byte) -49, (byte) 74, (byte) -34, (byte) 121, (byte) -117, (byte) -122, (byte) -111, (byte) -88, (byte) -29, (byte) 62, (byte) 66, (byte) -58, (byte) 81, (byte) -13, Handshake.SERVER_HELLO_DONE, (byte) 18, (byte) 54, (byte) 90, (byte) -18, (byte) 41, (byte) 123, (byte) -115, (byte) -116, (byte) -113, (byte) -118, (byte) -123, (byte) -108, (byte) -89, (byte) -14, (byte) 13, (byte) 23, (byte) 57, (byte) 75, (byte) -35, (byte) 124, (byte) -124, (byte) -105, (byte) -94, (byte) -3, (byte) 28, (byte) 36, (byte) 108, (byte) -76, (byte) -57, (byte) 82, (byte) -10, (byte) 1, (byte) 3, (byte) 5, Handshake.CERTIFICATE_VERIFY, (byte) 17, (byte) 51, (byte) 85, (byte) -1, (byte) 26, (byte) 46, (byte) 114, (byte) -106, (byte) -95, (byte) -8, (byte) 19, (byte) 53, (byte) 95, (byte) -31, (byte) 56, (byte) 72, (byte) -40, (byte) 115, (byte) -107, (byte) -92, (byte) -9, (byte) 2, (byte) 6, (byte) 10, (byte) 30, (byte) 34, (byte) 102, (byte) -86, (byte) -27, (byte) 52, (byte) 92, (byte) -28, (byte) 55, (byte) 89, (byte) -21, (byte) 38, (byte) 106, (byte) -66, (byte) -39, (byte) 112, (byte) -112, (byte) -85, (byte) -26, (byte) 49, (byte) 83, (byte) -11, (byte) 4, (byte) 12, Handshake.FINISHED, (byte) 60, (byte) 68, (byte) -52, (byte) 79, (byte) -47, (byte) 104, (byte) -72, (byte) -45, (byte) 110, (byte) -78, (byte) -51, (byte) 76, (byte) -44, (byte) 103, (byte) -87, (byte) -32, (byte) 59, (byte) 77, (byte) -41, (byte) 98, (byte) -90, (byte) -15, (byte) 8, (byte) 24, (byte) 40, (byte) 120, (byte) -120, (byte) -125, (byte) -98, (byte) -71, (byte) -48, (byte) 107, (byte) -67, (byte) -36, Byte.MAX_VALUE, (byte) -127, (byte) -104, (byte) -77, (byte) -50, (byte) 73, (byte) -37, (byte) 118, (byte) -102, (byte) -75, (byte) -60, (byte) 87, (byte) -7, (byte) 16, (byte) 48, (byte) 80, (byte) -16, (byte) 11, (byte) 29, (byte) 39, (byte) 105, (byte) -69, (byte) -42, (byte) 97, (byte) -93, (byte) -2, (byte) 25, (byte) 43, (byte) 125, (byte) -121, (byte) -110, (byte) -83, (byte) -20, (byte) 47, (byte) 113, (byte) -109, (byte) -82, (byte) -23, (byte) 32, (byte) 96, (byte) -96, (byte) -5, (byte) 22, (byte) 58, (byte) 78, (byte) -46, (byte) 109, (byte) -73, (byte) -62, (byte) 93, (byte) -25, (byte) 50, (byte) 86, (byte) -6, (byte) 21, (byte) 63, (byte) 65, (byte) -61, (byte) 94, (byte) -30, (byte) 61, (byte) 71, (byte) -55, (byte) 64, (byte) -64, (byte) 91, (byte) -19, (byte) 44, (byte) 116, (byte) -100, (byte) -65, (byte) -38, (byte) 117, (byte) -97, (byte) -70, (byte) -43, (byte) 100, (byte) -84, (byte) -17, (byte) 42, (byte) 126, (byte) -126, (byte) -99, (byte) -68, (byte) -33, (byte) 122, (byte) -114, (byte) -119, Byte.MIN_VALUE, (byte) -101, (byte) -74, (byte) -63, (byte) 88, (byte) -24, (byte) 35, (byte) 101, (byte) -81, (byte) -22, (byte) 37, (byte) 111, (byte) -79, (byte) -56, (byte) 67, (byte) -59, (byte) 84, (byte) -4, (byte) 31, (byte) 33, (byte) 99, (byte) -91, (byte) -12, (byte) 7, (byte) 9, (byte) 27, (byte) 45, (byte) 119, (byte) -103, (byte) -80, (byte) -53, (byte) 70, (byte) -54, (byte) 69, (byte) -49, (byte) 74, (byte) -34, (byte) 121, (byte) -117, (byte) -122, (byte) -111, (byte) -88, (byte) -29, (byte) 62, (byte) 66, (byte) -58, (byte) 81, (byte) -13, Handshake.SERVER_HELLO_DONE, (byte) 18, (byte) 54, (byte) 90, (byte) -18, (byte) 41, (byte) 123, (byte) -115, (byte) -116, (byte) -113, (byte) -118, (byte) -123, (byte) -108, (byte) -89, (byte) -14, (byte) 13, (byte) 23, (byte) 57, (byte) 75, (byte) -35, (byte) 124, (byte) -124, (byte) -105, (byte) -94, (byte) -3, (byte) 28, (byte) 36, (byte) 108, (byte) -76, (byte) -57, (byte) 82, (byte) -10, (byte) 1};
    private static final byte[] logtable = new byte[]{(byte) 0, (byte) 0, (byte) 25, (byte) 1, (byte) 50, (byte) 2, (byte) 26, (byte) -58, (byte) 75, (byte) -57, (byte) 27, (byte) 104, (byte) 51, (byte) -18, (byte) -33, (byte) 3, (byte) 100, (byte) 4, (byte) -32, Handshake.SERVER_HELLO_DONE, (byte) 52, (byte) -115, (byte) -127, (byte) -17, (byte) 76, (byte) 113, (byte) 8, (byte) -56, (byte) -8, (byte) 105, (byte) 28, (byte) -63, (byte) 125, (byte) -62, (byte) 29, (byte) -75, (byte) -7, (byte) -71, (byte) 39, (byte) 106, (byte) 77, (byte) -28, (byte) -90, (byte) 114, (byte) -102, (byte) -55, (byte) 9, (byte) 120, (byte) 101, (byte) 47, (byte) -118, (byte) 5, (byte) 33, Handshake.CERTIFICATE_VERIFY, (byte) -31, (byte) 36, (byte) 18, (byte) -16, (byte) -126, (byte) 69, (byte) 53, (byte) -109, (byte) -38, (byte) -114, (byte) -106, (byte) -113, (byte) -37, (byte) -67, (byte) 54, (byte) -48, (byte) -50, (byte) -108, (byte) 19, (byte) 92, (byte) -46, (byte) -15, (byte) 64, (byte) 70, (byte) -125, (byte) 56, (byte) 102, (byte) -35, (byte) -3, (byte) 48, (byte) -65, (byte) 6, (byte) -117, (byte) 98, (byte) -77, (byte) 37, (byte) -30, (byte) -104, (byte) 34, (byte) -120, (byte) -111, (byte) 16, (byte) 126, (byte) 110, (byte) 72, (byte) -61, (byte) -93, (byte) -74, (byte) 30, (byte) 66, (byte) 58, (byte) 107, (byte) 40, (byte) 84, (byte) -6, (byte) -123, (byte) 61, (byte) -70, (byte) 43, (byte) 121, (byte) 10, (byte) 21, (byte) -101, (byte) -97, (byte) 94, (byte) -54, (byte) 78, (byte) -44, (byte) -84, (byte) -27, (byte) -13, (byte) 115, (byte) -89, (byte) 87, (byte) -81, (byte) 88, (byte) -88, (byte) 80, (byte) -12, (byte) -22, (byte) -42, (byte) 116, (byte) 79, (byte) -82, (byte) -23, (byte) -43, (byte) -25, (byte) -26, (byte) -83, (byte) -24, (byte) 44, (byte) -41, (byte) 117, (byte) 122, (byte) -21, (byte) 22, (byte) 11, (byte) -11, (byte) 89, (byte) -53, (byte) 95, (byte) -80, (byte) -100, (byte) -87, (byte) 81, (byte) -96, Byte.MAX_VALUE, (byte) 12, (byte) -10, (byte) 111, (byte) 23, (byte) -60, (byte) 73, (byte) -20, (byte) -40, (byte) 67, (byte) 31, (byte) 45, (byte) -92, (byte) 118, (byte) 123, (byte) -73, (byte) -52, (byte) -69, (byte) 62, (byte) 90, (byte) -5, (byte) 96, (byte) -79, (byte) -122, (byte) 59, (byte) 82, (byte) -95, (byte) 108, (byte) -86, (byte) 85, (byte) 41, (byte) -99, (byte) -105, (byte) -78, (byte) -121, (byte) -112, (byte) 97, (byte) -66, (byte) -36, (byte) -4, (byte) -68, (byte) -107, (byte) -49, (byte) -51, (byte) 55, (byte) 63, (byte) 91, (byte) -47, (byte) 83, (byte) 57, (byte) -124, (byte) 60, (byte) 65, (byte) -94, (byte) 109, (byte) 71, Handshake.FINISHED, (byte) 42, (byte) -98, (byte) 93, (byte) 86, (byte) -14, (byte) -45, (byte) -85, (byte) 68, (byte) 17, (byte) -110, (byte) -39, (byte) 35, (byte) 32, (byte) 46, (byte) -119, (byte) -76, (byte) 124, (byte) -72, (byte) 38, (byte) 119, (byte) -103, (byte) -29, (byte) -91, (byte) 103, (byte) 74, (byte) -19, (byte) -34, (byte) -59, (byte) 49, (byte) -2, (byte) 24, (byte) 13, (byte) 99, (byte) -116, Byte.MIN_VALUE, (byte) -64, (byte) -9, (byte) 112, (byte) 7};
    private static final int[] rcon = new int[]{1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA, 47, 94, 188, 99, 198, CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA, 53, 106, 212, 179, EACTags.SECURE_MESSAGING_TEMPLATE, 250, 239, 197, 145};
    static byte[][] shifts0 = new byte[][]{new byte[]{(byte) 0, (byte) 8, (byte) 16, (byte) 24}, new byte[]{(byte) 0, (byte) 8, (byte) 16, (byte) 24}, new byte[]{(byte) 0, (byte) 8, (byte) 16, (byte) 24}, new byte[]{(byte) 0, (byte) 8, (byte) 16, (byte) 32}, new byte[]{(byte) 0, (byte) 8, (byte) 24, (byte) 32}};
    static byte[][] shifts1 = new byte[][]{new byte[]{(byte) 0, (byte) 24, (byte) 16, (byte) 8}, new byte[]{(byte) 0, (byte) 32, (byte) 24, (byte) 16}, new byte[]{(byte) 0, (byte) 40, (byte) 32, (byte) 24}, new byte[]{(byte) 0, (byte) 48, (byte) 40, (byte) 24}, new byte[]{(byte) 0, (byte) 56, (byte) 40, (byte) 32}};
    private long A0;
    private long A1;
    private long A2;
    private long A3;
    private int BC;
    private long BC_MASK;
    private int ROUNDS;
    private int blockBits;
    private boolean forEncryption;
    private byte[] shifts0SC;
    private byte[] shifts1SC;
    private long[][] workingKey;

    public RijndaelEngine() {
        this(128);
    }

    public RijndaelEngine(int i) {
        switch (i) {
            case 128:
                this.BC = 32;
                this.BC_MASK = 4294967295L;
                this.shifts0SC = shifts0[0];
                this.shifts1SC = shifts1[0];
                break;
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256 /*160*/:
                this.BC = 40;
                this.BC_MASK = 1099511627775L;
                this.shifts0SC = shifts0[1];
                this.shifts1SC = shifts1[1];
                break;
            case 192:
                this.BC = 48;
                this.BC_MASK = 281474976710655L;
                this.shifts0SC = shifts0[2];
                this.shifts1SC = shifts1[2];
                break;
            case 224:
                this.BC = 56;
                this.BC_MASK = 72057594037927935L;
                this.shifts0SC = shifts0[3];
                this.shifts1SC = shifts1[3];
                break;
            case 256:
                this.BC = 64;
                this.BC_MASK = -1;
                this.shifts0SC = shifts0[4];
                this.shifts1SC = shifts1[4];
                break;
            default:
                throw new IllegalArgumentException("unknown blocksize to Rijndael");
        }
        this.blockBits = i;
    }

    private void InvMixColumn() {
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        long j4 = 0;
        for (int i = 0; i < this.BC; i += 8) {
            int i2 = (int) ((this.A0 >> i) & 255);
            int i3 = (int) ((this.A1 >> i) & 255);
            int i4 = (int) ((this.A2 >> i) & 255);
            int i5 = (int) ((this.A3 >> i) & 255);
            int i6 = i2 != 0 ? logtable[i2 & 255] & 255 : -1;
            int i7 = i3 != 0 ? logtable[i3 & 255] & 255 : -1;
            i3 = i4 != 0 ? logtable[i4 & 255] & 255 : -1;
            i2 = i5 != 0 ? logtable[i5 & 255] & 255 : -1;
            j4 |= ((long) ((((mul0xe(i6) ^ mul0xb(i7)) ^ mul0xd(i3)) ^ mul0x9(i2)) & 255)) << i;
            j3 |= ((long) ((((mul0xe(i7) ^ mul0xb(i3)) ^ mul0xd(i2)) ^ mul0x9(i6)) & 255)) << i;
            j2 |= ((long) ((((mul0xe(i3) ^ mul0xb(i2)) ^ mul0xd(i6)) ^ mul0x9(i7)) & 255)) << i;
            j |= ((long) ((((mul0xe(i2) ^ mul0xb(i6)) ^ mul0xd(i7)) ^ mul0x9(i3)) & 255)) << i;
        }
        this.A0 = j4;
        this.A1 = j3;
        this.A2 = j2;
        this.A3 = j;
    }

    private void KeyAddition(long[] jArr) {
        this.A0 ^= jArr[0];
        this.A1 ^= jArr[1];
        this.A2 ^= jArr[2];
        this.A3 ^= jArr[3];
    }

    private void MixColumn() {
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        long j4 = 0;
        for (int i = 0; i < this.BC; i += 8) {
            int i2 = (int) ((this.A0 >> i) & 255);
            int i3 = (int) ((this.A1 >> i) & 255);
            int i4 = (int) ((this.A2 >> i) & 255);
            int i5 = (int) ((this.A3 >> i) & 255);
            j4 |= ((long) ((((mul0x2(i2) ^ mul0x3(i3)) ^ i4) ^ i5) & 255)) << i;
            j3 |= ((long) ((((mul0x2(i3) ^ mul0x3(i4)) ^ i5) ^ i2) & 255)) << i;
            j2 |= ((long) ((((mul0x2(i4) ^ mul0x3(i5)) ^ i2) ^ i3) & 255)) << i;
            j |= ((long) ((((mul0x3(i2) ^ mul0x2(i5)) ^ i3) ^ i4) & 255)) << i;
        }
        this.A0 = j4;
        this.A1 = j3;
        this.A2 = j2;
        this.A3 = j;
    }

    private void ShiftRow(byte[] bArr) {
        this.A1 = shift(this.A1, bArr[1]);
        this.A2 = shift(this.A2, bArr[2]);
        this.A3 = shift(this.A3, bArr[3]);
    }

    private void Substitution(byte[] bArr) {
        this.A0 = applyS(this.A0, bArr);
        this.A1 = applyS(this.A1, bArr);
        this.A2 = applyS(this.A2, bArr);
        this.A3 = applyS(this.A3, bArr);
    }

    private long applyS(long j, byte[] bArr) {
        long j2 = 0;
        for (int i = 0; i < this.BC; i += 8) {
            j2 |= ((long) (bArr[(int) ((j >> i) & 255)] & 255)) << i;
        }
        return j2;
    }

    private void decryptBlock(long[][] jArr) {
        KeyAddition(jArr[this.ROUNDS]);
        Substitution(Si);
        ShiftRow(this.shifts1SC);
        for (int i = this.ROUNDS - 1; i > 0; i--) {
            KeyAddition(jArr[i]);
            InvMixColumn();
            Substitution(Si);
            ShiftRow(this.shifts1SC);
        }
        KeyAddition(jArr[0]);
    }

    private void encryptBlock(long[][] jArr) {
        KeyAddition(jArr[0]);
        for (int i = 1; i < this.ROUNDS; i++) {
            Substitution(f246S);
            ShiftRow(this.shifts0SC);
            MixColumn();
            KeyAddition(jArr[i]);
        }
        Substitution(f246S);
        ShiftRow(this.shifts0SC);
        KeyAddition(jArr[this.ROUNDS]);
    }

    private long[][] generateWorkingKey(byte[] bArr) {
        int i;
        int i2;
        int length = bArr.length * 8;
        byte[][] bArr2 = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{4, 64});
        long[][] jArr = (long[][]) Array.newInstance(Long.TYPE, new int[]{15, 4});
        switch (length) {
            case 128:
                i = 4;
                break;
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256 /*160*/:
                i = 5;
                break;
            case 192:
                i = 6;
                break;
            case 224:
                i = 7;
                break;
            case 256:
                i = 8;
                break;
            default:
                throw new IllegalArgumentException("Key length not 128/160/192/224/256 bits.");
        }
        if (length >= this.blockBits) {
            this.ROUNDS = i + 6;
        } else {
            this.ROUNDS = (this.BC / 8) + 6;
        }
        int i3 = 0;
        length = 0;
        while (length < bArr.length) {
            i2 = i3 + 1;
            bArr2[length % 4][length / 4] = bArr[i3];
            length++;
            i3 = i2;
        }
        length = 0;
        for (i2 = 0; i2 < i && length < (this.ROUNDS + 1) * (this.BC / 8); i2++) {
            for (i3 = 0; i3 < 4; i3++) {
                long[] jArr2 = jArr[length / (this.BC / 8)];
                jArr2[i3] = jArr2[i3] | (((long) (bArr2[i3][i2] & 255)) << ((length * 8) % this.BC));
            }
            length++;
        }
        i2 = length;
        length = 0;
        while (i2 < (this.ROUNDS + 1) * (this.BC / 8)) {
            byte[] bArr3;
            int i4;
            for (i3 = 0; i3 < 4; i3++) {
                bArr3 = bArr2[i3];
                bArr3[0] = (byte) (bArr3[0] ^ f246S[bArr2[(i3 + 1) % 4][i - 1] & 255]);
            }
            bArr3 = bArr2[0];
            i3 = length + 1;
            bArr3[0] = (byte) (rcon[length] ^ bArr3[0]);
            byte[] bArr4;
            if (i <= 6) {
                for (i4 = 1; i4 < i; i4++) {
                    for (length = 0; length < 4; length++) {
                        bArr4 = bArr2[length];
                        bArr4[i4] = (byte) (bArr4[i4] ^ bArr2[length][i4 - 1]);
                    }
                }
            } else {
                for (i4 = 1; i4 < 4; i4++) {
                    for (length = 0; length < 4; length++) {
                        bArr4 = bArr2[length];
                        bArr4[i4] = (byte) (bArr4[i4] ^ bArr2[length][i4 - 1]);
                    }
                }
                for (length = 0; length < 4; length++) {
                    bArr3 = bArr2[length];
                    bArr3[4] = (byte) (bArr3[4] ^ f246S[bArr2[length][3] & 255]);
                }
                for (i4 = 5; i4 < i; i4++) {
                    for (length = 0; length < 4; length++) {
                        bArr4 = bArr2[length];
                        bArr4[i4] = (byte) (bArr4[i4] ^ bArr2[length][i4 - 1]);
                    }
                }
            }
            length = i2;
            for (i4 = 0; i4 < i && length < (this.ROUNDS + 1) * (this.BC / 8); i4++) {
                for (i2 = 0; i2 < 4; i2++) {
                    jArr2 = jArr[length / (this.BC / 8)];
                    jArr2[i2] = jArr2[i2] | (((long) (bArr2[i2][i4] & 255)) << ((length * 8) % this.BC));
                }
                length++;
            }
            i2 = length;
            length = i3;
        }
        return jArr;
    }

    private byte mul0x2(int i) {
        return i != 0 ? aLogtable[(logtable[i] & 255) + 25] : (byte) 0;
    }

    private byte mul0x3(int i) {
        return i != 0 ? aLogtable[(logtable[i] & 255) + 1] : (byte) 0;
    }

    private byte mul0x9(int i) {
        return i >= 0 ? aLogtable[i + 199] : (byte) 0;
    }

    private byte mul0xb(int i) {
        return i >= 0 ? aLogtable[i + 104] : (byte) 0;
    }

    private byte mul0xd(int i) {
        return i >= 0 ? aLogtable[i + 238] : (byte) 0;
    }

    private byte mul0xe(int i) {
        return i >= 0 ? aLogtable[i + 223] : (byte) 0;
    }

    private void packBlock(byte[] bArr, int i) {
        for (int i2 = 0; i2 != this.BC; i2 += 8) {
            int i3 = i + 1;
            bArr[i] = (byte) ((int) (this.A0 >> i2));
            int i4 = i3 + 1;
            bArr[i3] = (byte) ((int) (this.A1 >> i2));
            i3 = i4 + 1;
            bArr[i4] = (byte) ((int) (this.A2 >> i2));
            i = i3 + 1;
            bArr[i3] = (byte) ((int) (this.A3 >> i2));
        }
    }

    private long shift(long j, int i) {
        return ((j >>> i) | (j << (this.BC - i))) & this.BC_MASK;
    }

    private void unpackBlock(byte[] bArr, int i) {
        int i2 = i + 1;
        this.A0 = (long) (bArr[i] & 255);
        int i3 = i2 + 1;
        this.A1 = (long) (bArr[i2] & 255);
        i2 = i3 + 1;
        this.A2 = (long) (bArr[i3] & 255);
        i3 = i2 + 1;
        this.A3 = (long) (bArr[i2] & 255);
        for (i2 = 8; i2 != this.BC; i2 += 8) {
            int i4 = i3 + 1;
            this.A0 |= ((long) (bArr[i3] & 255)) << i2;
            i3 = i4 + 1;
            this.A1 |= ((long) (bArr[i4] & 255)) << i2;
            i4 = i3 + 1;
            this.A2 |= ((long) (bArr[i3] & 255)) << i2;
            i3 = i4 + 1;
            this.A3 |= ((long) (bArr[i4] & 255)) << i2;
        }
    }

    public String getAlgorithmName() {
        return "Rijndael";
    }

    public int getBlockSize() {
        return this.BC / 2;
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        if (cipherParameters instanceof KeyParameter) {
            this.workingKey = generateWorkingKey(((KeyParameter) cipherParameters).getKey());
            this.forEncryption = z;
            return;
        }
        throw new IllegalArgumentException("invalid parameter passed to Rijndael init - " + cipherParameters.getClass().getName());
    }

    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (this.workingKey == null) {
            throw new IllegalStateException("Rijndael engine not initialised");
        } else if ((this.BC / 2) + i > bArr.length) {
            throw new DataLengthException("input buffer too short");
        } else if ((this.BC / 2) + i2 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            if (this.forEncryption) {
                unpackBlock(bArr, i);
                encryptBlock(this.workingKey);
                packBlock(bArr2, i2);
            } else {
                unpackBlock(bArr, i);
                decryptBlock(this.workingKey);
                packBlock(bArr2, i2);
            }
            return this.BC / 2;
        }
    }

    public void reset() {
    }
}
