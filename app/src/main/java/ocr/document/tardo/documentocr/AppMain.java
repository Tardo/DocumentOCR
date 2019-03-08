/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.os.Environment;
import android.preference.PreferenceManager;
import android.util.Log;

import com.eiqui.odoojson_rpc.JSONRPCClientOdoo;
import com.googlecode.tesseract.android.TessBaseAPI;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;

import de.tsenger.androsmex.data.CANSpecDO;
import ocr.document.tardo.documentocr.utils.Constants;


public class AppMain extends Application {

    private static final String TAG = "AppMain";

    private static final String DATA_PATH = Environment
            .getExternalStorageDirectory().toString() + "/DocumentOCR/";
    private static final String TESS_LANG = "OCRB";

    protected JSONRPCClientOdoo mOdooClient;
    private SharedPreferences mSettings;

    private TessBaseAPI mTessApi;

    private CANSpecDO mSelectedCAN;
    public boolean mNFCStarted;

    public JSONRPCClientOdoo OdooClient() { return mOdooClient; }

    public void startOdooClient(String host, String dbname, int uid, String pass) throws MalformedURLException {
        mOdooClient = new JSONRPCClientOdoo(host);
        mOdooClient.setConfig(dbname, uid, pass);
    }

    public Integer getUID() {
        return mSettings.getInt("UserID", -1);
    }


    public void setCAN(CANSpecDO can)
    {
        mSelectedCAN = can;
    }

    public CANSpecDO getCAN()
    {
        return mSelectedCAN;
    }

    public boolean isStarted()
    {
        return mNFCStarted;
    }

    public void setStarted(boolean state)
    {
        mNFCStarted = state;
    }

    public TessBaseAPI getTessApi() { return mTessApi; }

    @Override
    public void onCreate() {
        // PreferenceManager.setDefaultValues(this, R.xml.prefs, false);
        mSettings = getApplicationContext().getSharedPreferences(Constants.SHARED_PREFS_USER_INFO, Context.MODE_PRIVATE);

        File tessdata = new File(DATA_PATH + "tessdata/" + TESS_LANG + ".traineddata");
        if (!tessdata.exists()) {
            tessdata.getParentFile().mkdirs();
            AssetManager assetManager = getAssets();
            try {
                InputStream in = assetManager.open("tessdata/" + TESS_LANG + ".traineddata");
                OutputStream out = new FileOutputStream(DATA_PATH + "tessdata/" + TESS_LANG + ".traineddata");

                // Transfer bytes from in to out
                byte[] buf = new byte[1024];
                int len;
                while ((len = in.read(buf)) > 0)
                    out.write(buf, 0, len);
                in.close();
                out.close();

                Log.v(TAG, "Copied " + TESS_LANG + " traineddata");
            } catch (IOException e) {
                Log.e(TAG, "Was unable to copy " + TESS_LANG + " traineddata " + e.toString());
            }
        }

        // Load Tesseract
        mTessApi = new TessBaseAPI();
        //mTessApi.setDebug(true);
        mTessApi.init(DATA_PATH, TESS_LANG);
        mTessApi.setVariable("load_system_dawg", "F");
        mTessApi.setVariable("load_freq_dawg", "F");
        mTessApi.setVariable("load_unambig_dawg", "F");
        mTessApi.setVariable("load_number_dawg", "F");
        mTessApi.setVariable("load_fixed_length_dawgs", "F");
        mTessApi.setVariable("load_bigram_dawg", "F");
        mTessApi.setVariable("wordrec_enable_assoc", "F");
        mTessApi.setVariable("tessedit_char_whitelist", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<");

        // Auto-Start
        int uid = getUID();
        if (uid != -1) {
            try {
                startOdooClient(mSettings.getString("Host", ""),
                        mSettings.getString("DBName", ""), uid,
                        mSettings.getString("Pass", ""));

            } catch (MalformedURLException e) {
                e.printStackTrace();
            }
        }

        super.onCreate();
    }

}
