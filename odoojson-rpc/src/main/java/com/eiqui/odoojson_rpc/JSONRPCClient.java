// Copyright 2018 - Alexandre Díaz - <dev@redneboa.es>
package com.eiqui.odoojson_rpc;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

/**
 * Created by uchar on 10/09/16.
 */
public class JSONRPCClient {
    final private static String USER_AGENT = "EIQUI JSON-RPC 0.3";
    final private static Integer MAX_CHUNK_LENGTH = 1024;
    final private URL mURL;


    public JSONRPCClient(String host) throws MalformedURLException {
        String host_protocol = host.split(":")[0];
        if (!Arrays.asList("http", "https").contains(host_protocol)) {
            host = "https://" + host;
        }
        mURL = new URL(host);
    }

    private HttpURLConnection startConnection() throws IOException {
        HttpURLConnection http;

        if (mURL.getProtocol().toLowerCase().equals("https")) {
            SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            HttpsURLConnection https = (HttpsURLConnection) mURL.openConnection();
            https.setSSLSocketFactory(sslsocketfactory);
            http = https;
        } else {
            http = (HttpURLConnection) mURL.openConnection();
        }

        http.setConnectTimeout(5000);
        http.setReadTimeout(20000);

        //add reuqest header
        http.setRequestMethod("POST");
        http.setRequestProperty("User-Agent", USER_AGENT);
        http.setRequestProperty("Content-Type", "application/json");
        http.setRequestProperty("Accept", "application/json");

        // Send post request
        http.setDoOutput(true);

        return http;
    }

    public JSONObject sendJSONObject(String method, JSONObject jsonObjParams) throws IOException {
        HttpURLConnection http = startConnection();
        if (http == null)
            return null;

        try {
            JSONObject jsonRPC = new JSONObject();
            jsonRPC.put("jsonrpc", "2.0");
            jsonRPC.put("id", String.valueOf(System.currentTimeMillis()));
            jsonRPC.put("method", method);
            jsonRPC.put("params", jsonObjParams);

            //http.setRequestProperty("Content-Length", Integer.toString(jsonRPC.toString().length()));

            InputStream stream = new ByteArrayInputStream(jsonRPC.toString().getBytes(StandardCharsets.UTF_8));
            DataOutputStream wr = new DataOutputStream(http.getOutputStream());
            byte[] buff = new byte[MAX_CHUNK_LENGTH];
            int bytesRead;
            while ((bytesRead = stream.read(buff)) != -1) {
                wr.write(buff, 0, bytesRead);
            }
            wr.flush();
            wr.close();

            int responseCode = http.getResponseCode();
            if (responseCode != 200)
                return null;

            BufferedReader in = new BufferedReader(new InputStreamReader(http.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            http.disconnect();

            return new JSONObject(response.toString());
        } catch (JSONException | IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}
