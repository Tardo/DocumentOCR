package es.inteco.labs.android.utils;

import android.content.Context;
import android.os.Build.VERSION;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public final class AndroidKeyStore {
    private static final int BUILD_ICS = 14;

    private AndroidKeyStore() {
    }

    public static final KeyStore getAndroidTruststore(Context ctx) {
        IOException e;
        KeyStoreException e2;
        Throwable th;
        NoSuchAlgorithmException e3;
        CertificateException e4;
        Exception e5;
        KeyStore keyStore = null;
        InputStream isTrustStore = null;
        try {
            if (VERSION.SDK_INT >= 14) {
                keyStore = KeyStore.getInstance("AndroidCAStore");
                keyStore.load(null, null);
                if (isTrustStore != null) {
                    try {
                        isTrustStore.close();
                    } catch (IOException e6) {
                        DNIeMovilLogger.m1e(e6);
                    }
                }
                return keyStore;
            }
            keyStore = KeyStore.getInstance("BKS");
            String path = System.getProperty("javax.net.ssl.trustStore");
            if (path == null) {
                path = System.getProperty("java.home") + File.separator + "etc" + File.separator + "security" + File.separator + "cacerts.bks";
            }
            InputStream isTrustStore2 = new FileInputStream(path);
            try {
                keyStore.load(isTrustStore2, null);
                if (isTrustStore2 != null) {
                    try {
                        isTrustStore2.close();
                        isTrustStore = isTrustStore2;
                    } catch (IOException e62) {
                        DNIeMovilLogger.m1e(e62);
                        isTrustStore = isTrustStore2;
                    }
                }
            } catch (KeyStoreException e7) {
                e2 = e7;
                isTrustStore = isTrustStore2;
                try {
                    DNIeMovilLogger.m1e(e2);
                    if (isTrustStore != null) {
                        try {
                            isTrustStore.close();
                        } catch (IOException e622) {
                            DNIeMovilLogger.m1e(e622);
                        }
                    }
                    return keyStore;
                } catch (Throwable th2) {
                    th = th2;
                    if (isTrustStore != null) {
                        try {
                            isTrustStore.close();
                        } catch (IOException e6222) {
                            DNIeMovilLogger.m1e(e6222);
                        }
                    }
                    throw th;
                }
            } catch (NoSuchAlgorithmException e8) {
                e3 = e8;
                isTrustStore = isTrustStore2;
                DNIeMovilLogger.m1e(e3);
                if (isTrustStore != null) {
                    try {
                        isTrustStore.close();
                    } catch (IOException e62222) {
                        DNIeMovilLogger.m1e(e62222);
                    }
                }
                return keyStore;
            } catch (CertificateException e9) {
                e4 = e9;
                isTrustStore = isTrustStore2;
                DNIeMovilLogger.m1e(e4);
                if (isTrustStore != null) {
                    try {
                        isTrustStore.close();
                    } catch (IOException e622222) {
                        DNIeMovilLogger.m1e(e622222);
                    }
                }
                return keyStore;
            } catch (IOException e10) {
                e622222 = e10;
                isTrustStore = isTrustStore2;
                DNIeMovilLogger.m1e(e622222);
                if (isTrustStore != null) {
                    try {
                        isTrustStore.close();
                    } catch (IOException e6222222) {
                        DNIeMovilLogger.m1e(e6222222);
                    }
                }
                return keyStore;
            } catch (Exception e11) {
                e5 = e11;
                isTrustStore = isTrustStore2;
                DNIeMovilLogger.m1e(e5);
                if (isTrustStore != null) {
                    try {
                        isTrustStore.close();
                    } catch (IOException e62222222) {
                        DNIeMovilLogger.m1e(e62222222);
                    }
                }
                return keyStore;
            } catch (Throwable th3) {
                th = th3;
                isTrustStore = isTrustStore2;
                if (isTrustStore != null) {
                    isTrustStore.close();
                }
                throw th;
            }
            return keyStore;
        } catch (KeyStoreException e12) {
            e2 = e12;
            DNIeMovilLogger.m1e(e2);
            if (isTrustStore != null) {
                isTrustStore.close();
            }
            return keyStore;
        } catch (NoSuchAlgorithmException e13) {
            e3 = e13;
            DNIeMovilLogger.m1e(e3);
            if (isTrustStore != null) {
                isTrustStore.close();
            }
            return keyStore;
        } catch (CertificateException e14) {
            e4 = e14;
            DNIeMovilLogger.m1e(e4);
            if (isTrustStore != null) {
                isTrustStore.close();
            }
            return keyStore;
        } catch (IOException e15) {
            e62222222 = e15;
            DNIeMovilLogger.m1e(e62222222);
            if (isTrustStore != null) {
                isTrustStore.close();
            }
            return keyStore;
        } catch (Exception e16) {
            e5 = e16;
            DNIeMovilLogger.m1e(e5);
            if (isTrustStore != null) {
                isTrustStore.close();
            }
            return keyStore;
        }
    }
}
