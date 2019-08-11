// Copyright 2018 - Alexandre Díaz - <dev@redneboa.es>
package com.eiqui.odoojson_rpc;

import android.util.Log;

import com.eiqui.odoojson_rpc.exceptions.OdooLoginException;
import com.eiqui.odoojson_rpc.exceptions.OdooSearchException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;

/**
 * Created by uchar on 10/09/16.
 */
public class JSONRPCClientOdoo {
    final static String RPC_URI = "/jsonrpc";
    final static public Integer ERROR = -1;
    final private JSONRPCClient mRPCClient;
    private String mDBName;
    private Integer mUID = -1;
    private String mPass;
    private String mLastError;


    static public String createStringDomain(String... domains) {
        try {
            JSONArray jsonArrayDomain = new JSONArray();
            for (String domain : domains) {
                jsonArrayDomain.put(new JSONArray(domain));
            }
            return jsonArrayDomain.toString();
        }catch (JSONException e) {
            e.printStackTrace();
        }

        return "[]";
    }

    public JSONRPCClientOdoo(String url) throws MalformedURLException {
        mRPCClient = new JSONRPCClient(url + RPC_URI, 0);
    }

    public String getLastError() { return mLastError; }

    private JSONObject sendJsonRpc(String service, String method, JSONArray args) throws JSONException {
        JSONObject jsonParams = new JSONObject();
        jsonParams.put("service", service);
        jsonParams.put("method", method);
        jsonParams.put("args", args);

        JSONObject jsonObjRes = null;
        try {
            jsonObjRes = mRPCClient.sendJSONObject("call", jsonParams);
            if (jsonObjRes == null)
                mLastError = "Server Internal Error";
            else {
                if (jsonObjRes.has("error"))
                    mLastError = jsonObjRes.getString("error");
                else
                    mLastError = "";
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return jsonObjRes;
    }

    public Object callObject(String service, String method, JSONArray args) throws JSONException {
        JSONObject jsonObj = sendJsonRpc(service, method, args);
        if (jsonObj == null)
            return -1;
        return jsonObj.get("result");
    }

    public Integer callInt(String service, String method, JSONArray args) throws JSONException {
        JSONObject jsonObj = sendJsonRpc(service, method, args);
        if (jsonObj == null)
            return -1;
        return jsonObj.getInt("result");
    }

    public JSONArray callJSONArray(String service, String method, JSONArray args) throws JSONException {
        JSONObject jsonObj = sendJsonRpc(service, method, args);
        if (jsonObj == null)
            return null;
        return jsonObj.getJSONArray("result");
    }

    public Boolean callBoolean(String service, String method, JSONArray args) throws JSONException {
        JSONObject jsonObj = sendJsonRpc(service, method, args);
        if (jsonObj == null)
            return Boolean.FALSE;
        return jsonObj.getBoolean("result");
    }

    public Integer loginIn(String login, String pass) throws OdooLoginException {
        Integer res = -1;
        try {
            JSONArray jsonArgs = new JSONArray();
            jsonArgs.put(mDBName);
            jsonArgs.put(login);
            jsonArgs.put(pass);

            Object obj = callObject("common", "login", jsonArgs);
            if (obj instanceof Integer)
                res = (Integer)obj;
        } catch (JSONException e) {
            e.printStackTrace();
            throw new OdooLoginException(e.getMessage());
        } catch (NumberFormatException e) {
            e.printStackTrace();
            throw new OdooLoginException(e.getMessage());
        }
        return res;
    }

    public void setConfig(String db, Integer uid, String pass) {
        mDBName = db;
        mUID = uid;
        mPass = pass;
    }

    public JSONArray callExecute(String operation, String model, String domain, String fields) throws OdooSearchException {
        JSONArray res = null;
        try {
            JSONArray jsonArgs = new JSONArray();
            jsonArgs.put(mDBName);
            jsonArgs.put(mUID);
            jsonArgs.put(mPass);
            jsonArgs.put(model);
            jsonArgs.put(operation);
            jsonArgs.put(new JSONArray(domain));
            if (fields != null)
                jsonArgs.put(new JSONArray(fields));

            res = callJSONArray("object", "execute", jsonArgs);
        } catch (JSONException e) {
            e.printStackTrace();
            throw new OdooSearchException(e.getMessage());
        }

        return res;
    }

    public JSONArray callSearch(String model, String domain, String fields) throws OdooSearchException {
        JSONArray res;
        try {
            JSONArray jsonArgs = new JSONArray();
            jsonArgs.put(mDBName);
            jsonArgs.put(mUID);
            jsonArgs.put(mPass);
            jsonArgs.put(model);
            jsonArgs.put("search_read");
            jsonArgs.put(new JSONArray(domain));
            jsonArgs.put(new JSONArray(fields));

            res = callJSONArray("object", "execute", jsonArgs);
        } catch (JSONException e) {
            e.printStackTrace();
            throw new OdooSearchException(e.getMessage());
        }

        return res;
    }

    public Integer callCount(String model, String domain) throws OdooSearchException {
        Integer res = 0;
        try {
            JSONArray jsonArgs = new JSONArray();
            jsonArgs.put(mDBName);
            jsonArgs.put(mUID);
            jsonArgs.put(mPass);
            jsonArgs.put(model);
            jsonArgs.put("search_count");
            jsonArgs.put(new JSONArray(domain));

            res = callInt("object", "execute", jsonArgs);
        } catch (JSONException e) {
            e.printStackTrace();
            throw new OdooSearchException(e.getMessage());
        }

        return res;
    }

    public int callCreate(String model, String values) throws OdooSearchException {
        int res;
        try {
            JSONArray jsonArgs = new JSONArray();
            jsonArgs.put(mDBName);
            jsonArgs.put(mUID);
            jsonArgs.put(mPass);
            jsonArgs.put(model);
            jsonArgs.put("create");
            jsonArgs.put(new JSONObject(values));

            res = callInt("object", "execute", jsonArgs);
        } catch (JSONException e) {
            e.printStackTrace();
            throw new OdooSearchException(e.getMessage());
        }

        return res;
    }

    public JSONArray getDBList() throws OdooSearchException {
        JSONArray res;
        try {
            res = callJSONArray("db", "list", new JSONArray());
        } catch (JSONException e) {
            e.printStackTrace();
            throw new OdooSearchException(e.getMessage());
        }

        return res;
    }
}
