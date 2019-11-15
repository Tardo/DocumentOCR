/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.nfc.Tag;
import android.os.Environment;
import android.util.Base64;
import android.util.Log;

import com.eiqui.odoojson_rpc.JSONRPCClientOdoo;
import com.googlecode.tesseract.android.TessBaseAPI;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import de.tsenger.androsmex.data.CANSpecDO;
import ocr.document.tardo.documentocr.utils.Constants;


public class AppMain extends Application {

    private static final String TAG = "AppMain";

    public static final String DATA_PATH = Environment
            .getExternalStorageDirectory().toString() + "/DocumentOCR/";
    public static final String TESS_LANG = "OCRB";

    protected JSONRPCClientOdoo mOdooClient;
    private SharedPreferences mSettings;

    private TessBaseAPI mTessApi;

    private CANSpecDO mSelectedCAN;

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

        // Instantiate Tesseract
        mTessApi = new TessBaseAPI();
        //mTessApi.setDebug(true);

        // Auto-Start
        boolean autoInit = false;
        int uid = getUID();
        if (uid != -1) {
            String passwd = "";
            try {
                byte[] encrypedPwdBytes = Base64.decode(mSettings.getString("Pass", ""), Base64.NO_WRAP);
                DESKeySpec keySpec = new DESKeySpec(Objects.requireNonNull(mSettings.getString("rn", "")).getBytes());
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
                SecretKey key = keyFactory.generateSecret(keySpec);
                Cipher cipher = Cipher.getInstance("DES/OFB32/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] plainTextPwdBytes = (cipher.doFinal(encrypedPwdBytes));
                passwd = new String(plainTextPwdBytes, StandardCharsets.UTF_8);
            } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | InvalidKeySpecException | IllegalBlockSizeException | IllegalArgumentException e) {
                e.printStackTrace(); // TODO: It's an error, don't hide & forget it ¬¬
            }

            if (!passwd.isEmpty()) {
                try {
                    startOdooClient(mSettings.getString("Host", ""),
                            mSettings.getString("DBName", ""), uid, passwd);
                    autoInit = true;
                } catch (MalformedURLException e) {
                    e.printStackTrace(); // TODO: It's an error, don't hide & forget it ¬¬
                }
            }
        }

        if (!autoInit) {
            SecureRandom sr = new SecureRandom();
            byte[] output = new byte[16];
            sr.nextBytes(output);
            SharedPreferences.Editor editor = mSettings.edit();
            editor.putString("rn", Base64.encodeToString(output, Base64.NO_WRAP));
            editor.apply();
        }

        super.onCreate();
    }

}
