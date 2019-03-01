package es.inteco.labs.net;

import android.content.Context;
import android.util.Log;
import android.webkit.CookieManager;
import android.webkit.CookieSyncManager;
import es.inteco.labs.android.utils.AndroidKeyStore;
import es.inteco.labs.net.auth.ClientCertSSLSocketFactory;
import java.io.IOException;
import java.net.URI;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.NameValuePair;
import org.apache.http.ProtocolException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultRedirectHandler;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

public final class DroidHttpClient {
    private static final int HTTP_TIMEOUT = 30000;
    private static CaCertificatesHandler caCertificatesHandler = null;
    private static DefaultHttpClient clientHttp = null;
    private static CookieStore cookieStore = null;
    private static HttpContext httpContext = null;
    public static boolean newCaCert = false;

    static class spaceRedirectHandler extends DefaultRedirectHandler {
        private static final String REDIRECT_LOCATIONS = "http.protocol.redirect-locations";
        private boolean bAlreadyRedirected = false;
        public String result;

        public boolean isRedirectRequested(HttpResponse response, HttpContext context) {
            if (response == null) {
                throw new IllegalArgumentException("HTTP response may not be null");
            }
            int statusCode = response.getStatusLine().getStatusCode();
            Log.d("REDIRECT!", "statusCode: " + statusCode);
            switch (statusCode) {
                case 301:
                case 302:
                case 303:
                case 307:
                    if (this.bAlreadyRedirected) {
                        return false;
                    }
                    this.bAlreadyRedirected = true;
                    return true;
                default:
                    return false;
            }
        }

        public URI getLocationURI(HttpResponse response, HttpContext context) throws ProtocolException {
            if (response == null) {
                throw new IllegalArgumentException("HTTP response may not be null");
            } else if (response.getFirstHeader("location") == null) {
                throw new ProtocolException("Received redirect response " + response.getStatusLine() + " but no location header");
            } else {
                try {
                    return new URI(EntityUtils.toString(response.getEntity()));
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new ProtocolException("Exception entityStr: ", e);
                }
            }
        }
    }

    private DroidHttpClient() {
    }

    protected static DefaultHttpClient getHttpClient(KeyStore ks, Set<String> certificadosAceptados, Context ctx) {
        if (clientHttp == null || newCaCert) {
            try {
                SSLSocketFactory sf;
                if (caCertificatesHandler != null) {
                    sf = new ClientCertSSLSocketFactory(ks, caCertificatesHandler.getCaKeyStore(), certificadosAceptados);
                    newCaCert = false;
                } else {
                    KeyStore trustStore = AndroidKeyStore.getAndroidTruststore(ctx);
                    if (trustStore == null) {
                        NetLogger.m7w("Error al cargar el TrustStore del Sistema Android");
                        trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                        trustStore.load(null, null);
                    }
                    sf = new ClientCertSSLSocketFactory(ks, trustStore, certificadosAceptados);
                }
                sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
                HttpParams params = new BasicHttpParams();
                HttpConnectionParams.setConnectionTimeout(params, HTTP_TIMEOUT);
                HttpConnectionParams.setSoTimeout(params, HTTP_TIMEOUT);
                HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
                HttpProtocolParams.setContentCharset(params, "UTF-8");
                SchemeRegistry registry = new SchemeRegistry();
                registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
                registry.register(new Scheme("https", sf, 443));
                clientHttp = new DefaultHttpClient(new ThreadSafeClientConnManager(params, registry), params);
                HttpClientParams.setCookiePolicy(clientHttp.getParams(), "rfc2109");
                clientHttp.getParams().setParameter("http.protocol.allow-circular-redirects", Boolean.valueOf(true));
                cookieStore = new BasicCookieStore();
                clientHttp.setCookieStore(cookieStore);
                httpContext = new BasicHttpContext();
                httpContext.setAttribute("http.cookie-store", cookieStore);
            } catch (Exception e) {
                DefaultHttpClient err = new DefaultHttpClient();
                cookieStore = new BasicCookieStore();
                httpContext = new BasicHttpContext();
                httpContext.setAttribute("http.cookie-store", cookieStore);
                err.setCookieStore(cookieStore);
                return err;
            }
        }
        return clientHttp;
    }

    public static void cleanCookies() {
        if (clientHttp != null && cookieStore != null) {
            cookieStore.clear();
            clientHttp = null;
        }
    }

    public static HttpEntity executeRequest(String url, Context ctx, KeyStore keyStore) throws ClientProtocolException, IOException {
        caCertificatesHandler = DNIeCaCertsManager.getCaCertHandler();
        String[] splittedUrl = url.split("\\?", 2);
        if (splittedUrl.length <= 1) {
            return executeHttpGet(url, ctx, keyStore);
        }
        if (splittedUrl[1].contains("?")) {
            String[] splittedUrl2 = splittedUrl[1].split("\\?", 2);
            splittedUrl[0] = splittedUrl[0] + "?" + splittedUrl2[0];
            splittedUrl[1] = splittedUrl2[1];
            url = splittedUrl[0];
        }
        return executeHttpPost(url, splittedUrl[1], ctx, keyStore);
    }

    public static String getContentType(HttpEntity entity) {
        return entity.getContentType().getValue().split(";")[0];
    }

    protected static HttpEntity executeMethod(HttpUriRequest request, Context ctx, KeyStore keyStore) throws ClientProtocolException, IOException {
        DefaultHttpClient client;
        if (caCertificatesHandler != null) {
            client = getHttpClient(keyStore, caCertificatesHandler.getValidCertificates(), ctx);
        } else {
            HashSet<String> trustedHostsSet = new HashSet();
            trustedHostsSet.add("B865130BEDCA38D27F69929420770BED86EFBC10");
            trustedHostsSet.add("82FD2A251ABB8824E6D70C2EEBC5FC32E12C915E");
            trustedHostsSet.add("‎1C5BFAA3DDE8C5A4A909D11037A50AEC0B4B21EC");
            trustedHostsSet.add("909BFE5235E1A31E11EB4EA4F880092372ED08EB");
            trustedHostsSet.add("B18D9D195669BA0F7829517566C25F422A277104");
            trustedHostsSet.add("43F9B110D5BAFD48225231B0D0082B372FEF9A54");
            trustedHostsSet.add("1933061EA82851CEF85CB8C477A80FD7E0306353");
            trustedHostsSet.add("ADD7098DC02EBC03C543F7C81B7E027E21A11E63");
            trustedHostsSet.add("CA93BDA233F3A55E8D3F1C09F7C9E300B012ACFA");
            trustedHostsSet.add("82FD2A251ABB8824E6D70C2EEBC5FC32E12C915E");
            trustedHostsSet.add("FAC9AED02749B97B965552981FD245FB3AB0F428");
            trustedHostsSet.add("E3296682A958B9D97610BB72DF62D38730A72CC8");
            trustedHostsSet.add("2D3E48B5671DB00B6EFA4AFEEACC034E8122ACAC");
            trustedHostsSet.add("B865130BEDCA38D27F69929420770BED86EFBC10");
            trustedHostsSet.add("‎1C5BFAA3DDE8C5A4A909D11037A50AEC0B4B21EC");
            trustedHostsSet.add("909BFE5235E1A31E11EB4EA4F880092372ED08EB");
            trustedHostsSet.add("C75C9E3BE1900E752F46DEBA590E6DCA4897971C");
            client = getHttpClient(keyStore, trustedHostsSet, ctx);
        }
        if (client.getCookieStore().clearExpired(Calendar.getInstance().getTime())) {
            NetLogger.m3d("Algunas cookies expiradas se eliminaron");
        }
        HttpResponse response = client.execute(request, httpContext);
        NetLogger.m3d(response.getStatusLine().getStatusCode() + ": " + response.getStatusLine().getReasonPhrase());
        synchronizeAndroidCookies(cookieStore, ctx);
        client.getConnectionManager().closeExpiredConnections();
        return response.getEntity();
    }

    protected static HttpEntity executeHttpGet(String url, Context contexto, KeyStore ks) throws ClientProtocolException, IOException {
        return executeMethod(new HttpGet(url), contexto, ks);
    }

    protected static HttpEntity executeHttpPost(String url, String parameters, Context contexto, KeyStore ks) throws ClientProtocolException, IOException {
        HttpPost post = new HttpPost(url);
        List<NameValuePair> paramList = new ArrayList();
        for (String parametro : parameters.split("&")) {
            String[] nv = parametro.split("=", 2);
            paramList.add(new BasicNameValuePair(nv[0], nv.length > 1 ? nv[1] : ""));
        }
        post.setEntity(new UrlEncodedFormEntity(paramList));
        return executeMethod(post, contexto, ks);
    }

    protected static void synchronizeAndroidCookies(CookieStore cookieStore, Context context) {
        List<Cookie> listaCookies = cookieStore.getCookies();
        if (!listaCookies.isEmpty()) {
            CookieSyncManager.createInstance(context);
            CookieManager cookieManager = CookieManager.getInstance();
            for (Cookie sessionInfo : listaCookies) {
                String cookieString = sessionInfo.getName() + "=" + sessionInfo.getValue() + "; domain=" + sessionInfo.getDomain();
                NetLogger.m3d(sessionInfo);
                cookieManager.setCookie(sessionInfo.getDomain(), cookieString);
                CookieSyncManager.getInstance().sync();
            }
        }
    }
}
