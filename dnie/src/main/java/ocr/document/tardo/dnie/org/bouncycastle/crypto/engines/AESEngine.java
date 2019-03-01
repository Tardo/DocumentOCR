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

public class AESEngine implements BlockCipher {
    private static final int BLOCK_SIZE = 16;
    /* renamed from: S */
    private static final byte[] f232S = new byte[]{(byte) 99, (byte) 124, (byte) 119, (byte) 123, (byte) -14, (byte) 107, (byte) 111, (byte) -59, (byte) 48, (byte) 1, (byte) 103, (byte) 43, (byte) -2, (byte) -41, (byte) -85, (byte) 118, (byte) -54, (byte) -126, (byte) -55, (byte) 125, (byte) -6, (byte) 89, (byte) 71, (byte) -16, (byte) -83, (byte) -44, (byte) -94, (byte) -81, (byte) -100, (byte) -92, (byte) 114, (byte) -64, (byte) -73, (byte) -3, (byte) -109, (byte) 38, (byte) 54, (byte) 63, (byte) -9, (byte) -52, (byte) 52, (byte) -91, (byte) -27, (byte) -15, (byte) 113, (byte) -40, (byte) 49, (byte) 21, (byte) 4, (byte) -57, (byte) 35, (byte) -61, (byte) 24, (byte) -106, (byte) 5, (byte) -102, (byte) 7, (byte) 18, Byte.MIN_VALUE, (byte) -30, (byte) -21, (byte) 39, (byte) -78, (byte) 117, (byte) 9, (byte) -125, (byte) 44, (byte) 26, (byte) 27, (byte) 110, (byte) 90, (byte) -96, (byte) 82, (byte) 59, (byte) -42, (byte) -77, (byte) 41, (byte) -29, (byte) 47, (byte) -124, (byte) 83, (byte) -47, (byte) 0, (byte) -19, (byte) 32, (byte) -4, (byte) -79, (byte) 91, (byte) 106, (byte) -53, (byte) -66, (byte) 57, (byte) 74, (byte) 76, (byte) 88, (byte) -49, (byte) -48, (byte) -17, (byte) -86, (byte) -5, (byte) 67, (byte) 77, (byte) 51, (byte) -123, (byte) 69, (byte) -7, (byte) 2, Byte.MAX_VALUE, (byte) 80, (byte) 60, (byte) -97, (byte) -88, (byte) 81, (byte) -93, (byte) 64, (byte) -113, (byte) -110, (byte) -99, (byte) 56, (byte) -11, (byte) -68, (byte) -74, (byte) -38, (byte) 33, (byte) 16, (byte) -1, (byte) -13, (byte) -46, (byte) -51, (byte) 12, (byte) 19, (byte) -20, (byte) 95, (byte) -105, (byte) 68, (byte) 23, (byte) -60, (byte) -89, (byte) 126, (byte) 61, (byte) 100, (byte) 93, (byte) 25, (byte) 115, (byte) 96, (byte) -127, (byte) 79, (byte) -36, (byte) 34, (byte) 42, (byte) -112, (byte) -120, (byte) 70, (byte) -18, (byte) -72, Handshake.FINISHED, (byte) -34, (byte) 94, (byte) 11, (byte) -37, (byte) -32, (byte) 50, (byte) 58, (byte) 10, (byte) 73, (byte) 6, (byte) 36, (byte) 92, (byte) -62, (byte) -45, (byte) -84, (byte) 98, (byte) -111, (byte) -107, (byte) -28, (byte) 121, (byte) -25, (byte) -56, (byte) 55, (byte) 109, (byte) -115, (byte) -43, (byte) 78, (byte) -87, (byte) 108, (byte) 86, (byte) -12, (byte) -22, (byte) 101, (byte) 122, (byte) -82, (byte) 8, (byte) -70, (byte) 120, (byte) 37, (byte) 46, (byte) 28, (byte) -90, (byte) -76, (byte) -58, (byte) -24, (byte) -35, (byte) 116, (byte) 31, (byte) 75, (byte) -67, (byte) -117, (byte) -118, (byte) 112, (byte) 62, (byte) -75, (byte) 102, (byte) 72, (byte) 3, (byte) -10, Handshake.SERVER_HELLO_DONE, (byte) 97, (byte) 53, (byte) 87, (byte) -71, (byte) -122, (byte) -63, (byte) 29, (byte) -98, (byte) -31, (byte) -8, (byte) -104, (byte) 17, (byte) 105, (byte) -39, (byte) -114, (byte) -108, (byte) -101, (byte) 30, (byte) -121, (byte) -23, (byte) -50, (byte) 85, (byte) 40, (byte) -33, (byte) -116, (byte) -95, (byte) -119, (byte) 13, (byte) -65, (byte) -26, (byte) 66, (byte) 104, (byte) 65, (byte) -103, (byte) 45, Handshake.CERTIFICATE_VERIFY, (byte) -80, (byte) 84, (byte) -69, (byte) 22};
    private static final byte[] Si = new byte[]{(byte) 82, (byte) 9, (byte) 106, (byte) -43, (byte) 48, (byte) 54, (byte) -91, (byte) 56, (byte) -65, (byte) 64, (byte) -93, (byte) -98, (byte) -127, (byte) -13, (byte) -41, (byte) -5, (byte) 124, (byte) -29, (byte) 57, (byte) -126, (byte) -101, (byte) 47, (byte) -1, (byte) -121, (byte) 52, (byte) -114, (byte) 67, (byte) 68, (byte) -60, (byte) -34, (byte) -23, (byte) -53, (byte) 84, (byte) 123, (byte) -108, (byte) 50, (byte) -90, (byte) -62, (byte) 35, (byte) 61, (byte) -18, (byte) 76, (byte) -107, (byte) 11, (byte) 66, (byte) -6, (byte) -61, (byte) 78, (byte) 8, (byte) 46, (byte) -95, (byte) 102, (byte) 40, (byte) -39, (byte) 36, (byte) -78, (byte) 118, (byte) 91, (byte) -94, (byte) 73, (byte) 109, (byte) -117, (byte) -47, (byte) 37, (byte) 114, (byte) -8, (byte) -10, (byte) 100, (byte) -122, (byte) 104, (byte) -104, (byte) 22, (byte) -44, (byte) -92, (byte) 92, (byte) -52, (byte) 93, (byte) 101, (byte) -74, (byte) -110, (byte) 108, (byte) 112, (byte) 72, (byte) 80, (byte) -3, (byte) -19, (byte) -71, (byte) -38, (byte) 94, (byte) 21, (byte) 70, (byte) 87, (byte) -89, (byte) -115, (byte) -99, (byte) -124, (byte) -112, (byte) -40, (byte) -85, (byte) 0, (byte) -116, (byte) -68, (byte) -45, (byte) 10, (byte) -9, (byte) -28, (byte) 88, (byte) 5, (byte) -72, (byte) -77, (byte) 69, (byte) 6, (byte) -48, (byte) 44, (byte) 30, (byte) -113, (byte) -54, (byte) 63, Handshake.CERTIFICATE_VERIFY, (byte) 2, (byte) -63, (byte) -81, (byte) -67, (byte) 3, (byte) 1, (byte) 19, (byte) -118, (byte) 107, (byte) 58, (byte) -111, (byte) 17, (byte) 65, (byte) 79, (byte) 103, (byte) -36, (byte) -22, (byte) -105, (byte) -14, (byte) -49, (byte) -50, (byte) -16, (byte) -76, (byte) -26, (byte) 115, (byte) -106, (byte) -84, (byte) 116, (byte) 34, (byte) -25, (byte) -83, (byte) 53, (byte) -123, (byte) -30, (byte) -7, (byte) 55, (byte) -24, (byte) 28, (byte) 117, (byte) -33, (byte) 110, (byte) 71, (byte) -15, (byte) 26, (byte) 113, (byte) 29, (byte) 41, (byte) -59, (byte) -119, (byte) 111, (byte) -73, (byte) 98, Handshake.SERVER_HELLO_DONE, (byte) -86, (byte) 24, (byte) -66, (byte) 27, (byte) -4, (byte) 86, (byte) 62, (byte) 75, (byte) -58, (byte) -46, (byte) 121, (byte) 32, (byte) -102, (byte) -37, (byte) -64, (byte) -2, (byte) 120, (byte) -51, (byte) 90, (byte) -12, (byte) 31, (byte) -35, (byte) -88, (byte) 51, (byte) -120, (byte) 7, (byte) -57, (byte) 49, (byte) -79, (byte) 18, (byte) 16, (byte) 89, (byte) 39, Byte.MIN_VALUE, (byte) -20, (byte) 95, (byte) 96, (byte) 81, Byte.MAX_VALUE, (byte) -87, (byte) 25, (byte) -75, (byte) 74, (byte) 13, (byte) 45, (byte) -27, (byte) 122, (byte) -97, (byte) -109, (byte) -55, (byte) -100, (byte) -17, (byte) -96, (byte) -32, (byte) 59, (byte) 77, (byte) -82, (byte) 42, (byte) -11, (byte) -80, (byte) -56, (byte) -21, (byte) -69, (byte) 60, (byte) -125, (byte) 83, (byte) -103, (byte) 97, (byte) 23, (byte) 43, (byte) 4, (byte) 126, (byte) -70, (byte) 119, (byte) -42, (byte) 38, (byte) -31, (byte) 105, Handshake.FINISHED, (byte) 99, (byte) 85, (byte) 33, (byte) 12, (byte) 125};
    private static final int[] T0 = new int[]{-1520213050, -2072216328, -1720223762, -1921287178, 234025727, -1117033514, -1318096930, 1422247313, 1345335392, 50397442, -1452841010, 2099981142, 436141799, 1658312629, -424957107, -1703512340, 1170918031, -1652391393, 1086966153, -2021818886, 368769775, -346465870, -918075506, 200339707, -324162239, 1742001331, -39673249, -357585083, -1080255453, -140204973, -1770884380, 1539358875, -1028147339, 486407649, -1366060227, 1780885068, 1513502316, 1094664062, 49805301, 1338821763, 1546925160, -190470831, 887481809, 150073849, -1821281822, 1943591083, 1395732834, 1058346282, 201589768, 1388824469, 1696801606, 1589887901, 672667696, -1583966665, 251987210, -1248159185, 151455502, 907153956, -1686077413, 1038279391, 652995533, 1764173646, -843926913, -1619692054, 453576978, -1635548387, 1949051992, 773462580, 756751158, -1301385508, -296068428, -73359269, -162377052, 1295727478, 1641469623, -827083907, 2066295122, 1055122397, 1898917726, -1752923117, -179088474, 1758581177, 0, 753790401, 1612718144, 536673507, -927878791, -312779850, -1100322092, 1187761037, -641810841, 1262041458, -565556588, -733197160, -396863312, 1255133061, 1808847035, 720367557, -441800113, 385612781, -985447546, -682799718, 1429418854, -1803188975, -817543798, 284817897, 100794884, -2122350594, -263171936, 1144798328, -1163944155, -475486133, -212774494, -22830243, -1069531008, -1970303227, -1382903233, -1130521311, 1211644016, 83228145, -541279133, -1044990345, 1977277103, 1663115586, 806359072, 452984805, 250868733, 1842533055, 1288555905, 336333848, 890442534, 804056259, -513843266, -1567123659, -867941240, 957814574, 1472513171, -223893675, -2105639172, 1195195770, -1402706744, -413311558, 723065138, -1787595802, -1604296512, -1736343271, -783331426, 2145180835, 1713513028, 2116692564, -1416589253, -2088204277, -901364084, 703524551, -742868885, 1007948840, 2044649127, -497131844, 487262998, 1994120109, 1004593371, 1446130276, 1312438900, 503974420, -615954030, 168166924, 1814307912, -463709000, 1573044895, 1859376061, -273896381, -1503501628, -1466855111, -1533700815, 937747667, -1954973198, 854058965, 1137232011, 1496790894, -1217565222, -1936880383, 1691735473, -766620004, -525751991, -1267962664, -95005012, 133494003, 636152527, -1352309302, -1904575756, -374428089, 403179536, -709182865, -2005370640, 1864705354, 1915629148, 605822008, -240736681, -944458637, 1371981463, 602466507, 2094914977, -1670089496, 555687742, -582268010, -591544991, -2037675251, -2054518257, -1871679264, 1111375484, -994724495, -1436129588, -666351472, 84083462, 32962295, 302911004, -1553899070, 1597322602, -111716434, -793134743, -1853454825, 1489093017, 656219450, -1180787161, 954327513, 335083755, -1281845205, 856756514, -1150719534, 1893325225, -1987146233, -1483434957, -1231316179, 572399164, -1836611819, 552200649, 1238290055, -11184726, 2015897680, 2061492133, -1886614525, -123625127, -2138470135, 386731290, -624967835, 837215959, -968736124, -1201116976, -1019133566, -1332111063, 1999449434, 286199582, -877612933, -61582168, -692339859, 974525996};
    private static final int[] Tinv0 = new int[]{1353184337, 1399144830, -1012656358, -1772214470, -882136261, -247096033, -1420232020, -1828461749, 1442459680, -160598355, -1854485368, 625738485, -52959921, -674551099, -2143013594, -1885117771, 1230680542, 1729870373, -1743852987, -507445667, 41234371, 317738113, -1550367091, -956705941, -413167869, -1784901099, -344298049, -631680363, 763608788, -752782248, 694804553, 1154009486, 1787413109, 2021232372, 1799248025, -579749593, -1236278850, 397248752, 1722556617, -1271214467, 407560035, -2110711067, 1613975959, 1165972322, -529046351, -2068943941, 480281086, -1809118983, 1483229296, 436028815, -2022908268, -1208452270, 601060267, -503166094, 1468997603, 715871590, 120122290, 63092015, -1703164538, -1526188077, -226023376, -1297760477, -1167457534, 1552029421, 723308426, -1833666137, -252573709, -1578997426, -839591323, -708967162, 526529745, -1963022652, -1655493068, -1604979806, 853641733, 1978398372, 971801355, -1427152832, 111112542, 1360031421, -108388034, 1023860118, -1375387939, 1186850381, -1249028975, 90031217, 1876166148, -15380384, 620468249, -1746289194, -868007799, 2006899047, -1119688528, -2004121337, 945494503, -605108103, 1191869601, -384875908, -920746760, 0, -2088337399, 1223502642, -1401941730, 1316117100, -67170563, 1446544655, 517320253, 658058550, 1691946762, 564550760, -783000677, 976107044, -1318647284, 266819475, -761860428, -1634624741, 1338359936, -1574904735, 1766553434, 370807324, 179999714, -450191168, 1138762300, 488053522, 185403662, -1379431438, -1180125651, -928440812, -2061897385, 1275557295, -1143105042, -44007517, -1624899081, -1124765092, -985962940, 880737115, 1982415755, -590994485, 1761406390, 1676797112, -891538985, 277177154, 1076008723, 538035844, 2099530373, -130171950, 288553390, 1839278535, 1261411869, -214912292, -330136051, -790380169, 1813426987, -1715900247, -95906799, 577038663, -997393240, 440397984, -668172970, -275762398, -951170681, -1043253031, -22885748, 906744984, -813566554, 685669029, 646887386, -1530942145, -459458004, 227702864, -1681105046, 1648787028, -1038905866, -390539120, 1593260334, -173030526, -1098883681, 2090061929, -1456614033, -1290656305, 999926984, -1484974064, 1852021992, 2075868123, 158869197, -199730834, 28809964, -1466282109, 1701746150, 2129067946, 147831841, -420997649, -644094022, -835293366, -737566742, -696471511, -1347247055, 824393514, 815048134, -1067015627, 935087732, -1496677636, -1328508704, 366520115, 1251476721, -136647615, 240176511, 804688151, -1915335306, 1303441219, 1414376140, -553347356, -474623586, 461924940, -1205916479, 2136040774, 82468509, 1563790337, 1937016826, 776014843, 1511876531, 1389550482, 861278441, 323475053, -1939744870, 2047648055, -1911228327, -1992551445, -299390514, 902390199, -303751967, 1018251130, 1507840668, 1064563285, 2043548696, -1086863501, -355600557, 1537932639, 342834655, -2032450440, -2114736182, 1053059257, 741614648, 1598071746, 1925389590, 203809468, -1958134744, 1100287487, 1895934009, -558691320, -1662733096, -1866377628, 1636092795, 1890988757, 1952214088, 1113045200};
    private static final int m1 = -2139062144;
    private static final int m2 = 2139062143;
    private static final int m3 = 27;
    private static final int[] rcon = new int[]{1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA, 47, 94, 188, 99, 198, CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA, 53, 106, 212, 179, EACTags.SECURE_MESSAGING_TEMPLATE, 250, 239, 197, 145};
    private int C0;
    private int C1;
    private int C2;
    private int C3;
    private int ROUNDS;
    private int[][] WorkingKey = ((int[][]) null);
    private boolean forEncryption;

    private static int FFmulX(int i) {
        return ((m2 & i) << 1) ^ (((m1 & i) >>> 7) * 27);
    }

    private void decryptBlock(int[][] iArr) {
        int shift;
        int shift2;
        int shift3;
        this.C0 ^= iArr[this.ROUNDS][0];
        this.C1 ^= iArr[this.ROUNDS][1];
        this.C2 ^= iArr[this.ROUNDS][2];
        this.C3 ^= iArr[this.ROUNDS][3];
        int i = this.ROUNDS - 1;
        while (i > 1) {
            shift = (((Tinv0[this.C0 & 255] ^ shift(Tinv0[(this.C3 >> 8) & 255], 24)) ^ shift(Tinv0[(this.C2 >> 16) & 255], 16)) ^ shift(Tinv0[(this.C1 >> 24) & 255], 8)) ^ iArr[i][0];
            shift2 = (((Tinv0[this.C1 & 255] ^ shift(Tinv0[(this.C0 >> 8) & 255], 24)) ^ shift(Tinv0[(this.C3 >> 16) & 255], 16)) ^ shift(Tinv0[(this.C2 >> 24) & 255], 8)) ^ iArr[i][1];
            shift3 = (((Tinv0[this.C2 & 255] ^ shift(Tinv0[(this.C1 >> 8) & 255], 24)) ^ shift(Tinv0[(this.C0 >> 16) & 255], 16)) ^ shift(Tinv0[(this.C3 >> 24) & 255], 8)) ^ iArr[i][2];
            int i2 = i - 1;
            i = iArr[i][3] ^ (((Tinv0[this.C3 & 255] ^ shift(Tinv0[(this.C2 >> 8) & 255], 24)) ^ shift(Tinv0[(this.C1 >> 16) & 255], 16)) ^ shift(Tinv0[(this.C0 >> 24) & 255], 8));
            this.C0 = (((Tinv0[shift & 255] ^ shift(Tinv0[(i >> 8) & 255], 24)) ^ shift(Tinv0[(shift3 >> 16) & 255], 16)) ^ shift(Tinv0[(shift2 >> 24) & 255], 8)) ^ iArr[i2][0];
            this.C1 = (((Tinv0[shift2 & 255] ^ shift(Tinv0[(shift >> 8) & 255], 24)) ^ shift(Tinv0[(i >> 16) & 255], 16)) ^ shift(Tinv0[(shift3 >> 24) & 255], 8)) ^ iArr[i2][1];
            this.C2 = (((Tinv0[shift3 & 255] ^ shift(Tinv0[(shift2 >> 8) & 255], 24)) ^ shift(Tinv0[(shift >> 16) & 255], 16)) ^ shift(Tinv0[(i >> 24) & 255], 8)) ^ iArr[i2][2];
            shift = shift(Tinv0[(shift >> 24) & 255], 8) ^ ((Tinv0[i & 255] ^ shift(Tinv0[(shift3 >> 8) & 255], 24)) ^ shift(Tinv0[(shift2 >> 16) & 255], 16));
            i = i2 - 1;
            this.C3 = shift ^ iArr[i2][3];
        }
        shift = (((Tinv0[this.C0 & 255] ^ shift(Tinv0[(this.C3 >> 8) & 255], 24)) ^ shift(Tinv0[(this.C2 >> 16) & 255], 16)) ^ shift(Tinv0[(this.C1 >> 24) & 255], 8)) ^ iArr[i][0];
        shift2 = (((Tinv0[this.C1 & 255] ^ shift(Tinv0[(this.C0 >> 8) & 255], 24)) ^ shift(Tinv0[(this.C3 >> 16) & 255], 16)) ^ shift(Tinv0[(this.C2 >> 24) & 255], 8)) ^ iArr[i][1];
        shift3 = (((Tinv0[this.C2 & 255] ^ shift(Tinv0[(this.C1 >> 8) & 255], 24)) ^ shift(Tinv0[(this.C0 >> 16) & 255], 16)) ^ shift(Tinv0[(this.C3 >> 24) & 255], 8)) ^ iArr[i][2];
        i = iArr[i][3] ^ (((Tinv0[this.C3 & 255] ^ shift(Tinv0[(this.C2 >> 8) & 255], 24)) ^ shift(Tinv0[(this.C1 >> 16) & 255], 16)) ^ shift(Tinv0[(this.C0 >> 24) & 255], 8));
        this.C0 = ((((Si[shift & 255] & 255) ^ ((Si[(i >> 8) & 255] & 255) << 8)) ^ ((Si[(shift3 >> 16) & 255] & 255) << 16)) ^ (Si[(shift2 >> 24) & 255] << 24)) ^ iArr[0][0];
        this.C1 = ((((Si[shift2 & 255] & 255) ^ ((Si[(shift >> 8) & 255] & 255) << 8)) ^ ((Si[(i >> 16) & 255] & 255) << 16)) ^ (Si[(shift3 >> 24) & 255] << 24)) ^ iArr[0][1];
        this.C2 = ((((Si[shift3 & 255] & 255) ^ ((Si[(shift2 >> 8) & 255] & 255) << 8)) ^ ((Si[(shift >> 16) & 255] & 255) << 16)) ^ (Si[(i >> 24) & 255] << 24)) ^ iArr[0][2];
        this.C3 = ((((Si[i & 255] & 255) ^ ((Si[(shift3 >> 8) & 255] & 255) << 8)) ^ ((Si[(shift2 >> 16) & 255] & 255) << 16)) ^ (Si[(shift >> 24) & 255] << 24)) ^ iArr[0][3];
    }

    private void encryptBlock(int[][] iArr) {
        int shift;
        int shift2;
        int shift3;
        int i;
        this.C0 ^= iArr[0][0];
        this.C1 ^= iArr[0][1];
        this.C2 ^= iArr[0][2];
        this.C3 ^= iArr[0][3];
        int i2 = 1;
        while (i2 < this.ROUNDS - 1) {
            shift = (((T0[this.C0 & 255] ^ shift(T0[(this.C1 >> 8) & 255], 24)) ^ shift(T0[(this.C2 >> 16) & 255], 16)) ^ shift(T0[(this.C3 >> 24) & 255], 8)) ^ iArr[i2][0];
            shift2 = (((T0[this.C1 & 255] ^ shift(T0[(this.C2 >> 8) & 255], 24)) ^ shift(T0[(this.C3 >> 16) & 255], 16)) ^ shift(T0[(this.C0 >> 24) & 255], 8)) ^ iArr[i2][1];
            shift3 = (((T0[this.C2 & 255] ^ shift(T0[(this.C3 >> 8) & 255], 24)) ^ shift(T0[(this.C0 >> 16) & 255], 16)) ^ shift(T0[(this.C1 >> 24) & 255], 8)) ^ iArr[i2][2];
            i = i2 + 1;
            i2 = iArr[i2][3] ^ (((T0[this.C3 & 255] ^ shift(T0[(this.C0 >> 8) & 255], 24)) ^ shift(T0[(this.C1 >> 16) & 255], 16)) ^ shift(T0[(this.C2 >> 24) & 255], 8));
            this.C0 = (((T0[shift & 255] ^ shift(T0[(shift2 >> 8) & 255], 24)) ^ shift(T0[(shift3 >> 16) & 255], 16)) ^ shift(T0[(i2 >> 24) & 255], 8)) ^ iArr[i][0];
            this.C1 = (((T0[shift2 & 255] ^ shift(T0[(shift3 >> 8) & 255], 24)) ^ shift(T0[(i2 >> 16) & 255], 16)) ^ shift(T0[(shift >> 24) & 255], 8)) ^ iArr[i][1];
            this.C2 = (((T0[shift3 & 255] ^ shift(T0[(i2 >> 8) & 255], 24)) ^ shift(T0[(shift >> 16) & 255], 16)) ^ shift(T0[(shift2 >> 24) & 255], 8)) ^ iArr[i][2];
            shift = shift(T0[(shift3 >> 24) & 255], 8) ^ ((T0[i2 & 255] ^ shift(T0[(shift >> 8) & 255], 24)) ^ shift(T0[(shift2 >> 16) & 255], 16));
            i2 = i + 1;
            this.C3 = shift ^ iArr[i][3];
        }
        shift = (((T0[this.C0 & 255] ^ shift(T0[(this.C1 >> 8) & 255], 24)) ^ shift(T0[(this.C2 >> 16) & 255], 16)) ^ shift(T0[(this.C3 >> 24) & 255], 8)) ^ iArr[i2][0];
        shift2 = (((T0[this.C1 & 255] ^ shift(T0[(this.C2 >> 8) & 255], 24)) ^ shift(T0[(this.C3 >> 16) & 255], 16)) ^ shift(T0[(this.C0 >> 24) & 255], 8)) ^ iArr[i2][1];
        shift3 = (((T0[this.C2 & 255] ^ shift(T0[(this.C3 >> 8) & 255], 24)) ^ shift(T0[(this.C0 >> 16) & 255], 16)) ^ shift(T0[(this.C1 >> 24) & 255], 8)) ^ iArr[i2][2];
        i = i2 + 1;
        i2 = iArr[i2][3] ^ (((T0[this.C3 & 255] ^ shift(T0[(this.C0 >> 8) & 255], 24)) ^ shift(T0[(this.C1 >> 16) & 255], 16)) ^ shift(T0[(this.C2 >> 24) & 255], 8));
        this.C0 = ((((f232S[shift & 255] & 255) ^ ((f232S[(shift2 >> 8) & 255] & 255) << 8)) ^ ((f232S[(shift3 >> 16) & 255] & 255) << 16)) ^ (f232S[(i2 >> 24) & 255] << 24)) ^ iArr[i][0];
        this.C1 = iArr[i][1] ^ ((((f232S[shift2 & 255] & 255) ^ ((f232S[(shift3 >> 8) & 255] & 255) << 8)) ^ ((f232S[(i2 >> 16) & 255] & 255) << 16)) ^ (f232S[(shift >> 24) & 255] << 24));
        this.C2 = ((((f232S[shift3 & 255] & 255) ^ ((f232S[(i2 >> 8) & 255] & 255) << 8)) ^ ((f232S[(shift >> 16) & 255] & 255) << 16)) ^ (f232S[(shift2 >> 24) & 255] << 24)) ^ iArr[i][2];
        this.C3 = ((((f232S[i2 & 255] & 255) ^ ((f232S[(shift >> 8) & 255] & 255) << 8)) ^ ((f232S[(shift2 >> 16) & 255] & 255) << 16)) ^ (f232S[(shift3 >> 24) & 255] << 24)) ^ iArr[i][3];
    }

    private int[][] generateWorkingKey(byte[] bArr, boolean z) {
        int length = bArr.length / 4;
        if ((length == 4 || length == 6 || length == 8) && length * 4 == bArr.length) {
            this.ROUNDS = length + 6;
            int[][] iArr = (int[][]) Array.newInstance(Integer.TYPE, new int[]{this.ROUNDS + 1, 4});
            int i = 0;
            int i2 = 0;
            while (i < bArr.length) {
                iArr[i2 >> 2][i2 & 3] = (((bArr[i] & 255) | ((bArr[i + 1] & 255) << 8)) | ((bArr[i + 2] & 255) << 16)) | (bArr[i + 3] << 24);
                i += 4;
                i2++;
            }
            int i3 = (this.ROUNDS + 1) << 2;
            i2 = length;
            while (i2 < i3) {
                i = iArr[(i2 - 1) >> 2][(i2 - 1) & 3];
                if (i2 % length == 0) {
                    i = subWord(shift(i, 8)) ^ rcon[(i2 / length) - 1];
                } else if (length > 6 && i2 % length == 4) {
                    i = subWord(i);
                }
                iArr[i2 >> 2][i2 & 3] = i ^ iArr[(i2 - length) >> 2][(i2 - length) & 3];
                i2++;
            }
            if (!z) {
                for (i = 1; i < this.ROUNDS; i++) {
                    for (i2 = 0; i2 < 4; i2++) {
                        iArr[i][i2] = inv_mcol(iArr[i][i2]);
                    }
                }
            }
            return iArr;
        }
        throw new IllegalArgumentException("Key length not 128/192/256 bits.");
    }

    private static int inv_mcol(int i) {
        int FFmulX = FFmulX(i);
        int FFmulX2 = FFmulX(FFmulX);
        int FFmulX3 = FFmulX(FFmulX2);
        int i2 = i ^ FFmulX3;
        return ((shift(FFmulX ^ i2, 8) ^ (FFmulX3 ^ (FFmulX ^ FFmulX2))) ^ shift(FFmulX2 ^ i2, 16)) ^ shift(i2, 24);
    }

    private void packBlock(byte[] bArr, int i) {
        int i2 = i + 1;
        bArr[i] = (byte) this.C0;
        int i3 = i2 + 1;
        bArr[i2] = (byte) (this.C0 >> 8);
        i2 = i3 + 1;
        bArr[i3] = (byte) (this.C0 >> 16);
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C0 >> 24);
        i2 = i3 + 1;
        bArr[i3] = (byte) this.C1;
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C1 >> 8);
        i2 = i3 + 1;
        bArr[i3] = (byte) (this.C1 >> 16);
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C1 >> 24);
        i2 = i3 + 1;
        bArr[i3] = (byte) this.C2;
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C2 >> 8);
        i2 = i3 + 1;
        bArr[i3] = (byte) (this.C2 >> 16);
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C2 >> 24);
        i2 = i3 + 1;
        bArr[i3] = (byte) this.C3;
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C3 >> 8);
        i2 = i3 + 1;
        bArr[i3] = (byte) (this.C3 >> 16);
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C3 >> 24);
    }

    private static int shift(int i, int i2) {
        return (i >>> i2) | (i << (-i2));
    }

    private static int subWord(int i) {
        return (((f232S[i & 255] & 255) | ((f232S[(i >> 8) & 255] & 255) << 8)) | ((f232S[(i >> 16) & 255] & 255) << 16)) | (f232S[(i >> 24) & 255] << 24);
    }

    private void unpackBlock(byte[] bArr, int i) {
        int i2 = i + 1;
        this.C0 = bArr[i] & 255;
        int i3 = i2 + 1;
        this.C0 = ((bArr[i2] & 255) << 8) | this.C0;
        int i4 = i3 + 1;
        this.C0 |= (bArr[i3] & 255) << 16;
        i3 = i4 + 1;
        this.C0 |= bArr[i4] << 24;
        i2 = i3 + 1;
        this.C1 = bArr[i3] & 255;
        i3 = i2 + 1;
        this.C1 = ((bArr[i2] & 255) << 8) | this.C1;
        i4 = i3 + 1;
        this.C1 |= (bArr[i3] & 255) << 16;
        i3 = i4 + 1;
        this.C1 |= bArr[i4] << 24;
        i2 = i3 + 1;
        this.C2 = bArr[i3] & 255;
        i3 = i2 + 1;
        this.C2 = ((bArr[i2] & 255) << 8) | this.C2;
        i4 = i3 + 1;
        this.C2 |= (bArr[i3] & 255) << 16;
        i3 = i4 + 1;
        this.C2 |= bArr[i4] << 24;
        i2 = i3 + 1;
        this.C3 = bArr[i3] & 255;
        i3 = i2 + 1;
        this.C3 = ((bArr[i2] & 255) << 8) | this.C3;
        i4 = i3 + 1;
        this.C3 |= (bArr[i3] & 255) << 16;
        i3 = i4 + 1;
        this.C3 |= bArr[i4] << 24;
    }

    public String getAlgorithmName() {
        return "AES";
    }

    public int getBlockSize() {
        return 16;
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        if (cipherParameters instanceof KeyParameter) {
            this.WorkingKey = generateWorkingKey(((KeyParameter) cipherParameters).getKey(), z);
            this.forEncryption = z;
            return;
        }
        throw new IllegalArgumentException("invalid parameter passed to AES init - " + cipherParameters.getClass().getName());
    }

    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (this.WorkingKey == null) {
            throw new IllegalStateException("AES engine not initialised");
        } else if (i + 16 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        } else if (i2 + 16 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            if (this.forEncryption) {
                unpackBlock(bArr, i);
                encryptBlock(this.WorkingKey);
                packBlock(bArr2, i2);
            } else {
                unpackBlock(bArr, i);
                decryptBlock(this.WorkingKey);
                packBlock(bArr2, i2);
            }
            return 16;
        }
    }

    public void reset() {
    }
}
