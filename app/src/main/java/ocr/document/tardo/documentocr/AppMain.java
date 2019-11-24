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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.tsenger.androsmex.data.CANSpecDO;
import ocr.document.tardo.documentocr.utils.Constants;


public class AppMain extends Application {

    private static final String TAG = "AppMain";
    private static final String CIPHER_METHOD = "AES/CBC/PKCS5Padding";

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

    public String getUserPassword() {
        String passwd;
        try {
            final IvParameterSpec iv = new IvParameterSpec(Base64.decode(mSettings.getString("iv", ""), Base64.NO_WRAP));
            final SecretKeySpec keySpec = new SecretKeySpec(Base64.decode(mSettings.getString("rn", ""), Base64.NO_WRAP), CIPHER_METHOD.split("/")[0]);
            final Cipher cipher = Cipher.getInstance(CIPHER_METHOD);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
            final byte[] encryptedPwdBytes = Base64.decode(mSettings.getString("Pass", ""), Base64.NO_WRAP);
            final byte[] plainTextPwdBytes = cipher.doFinal(encryptedPwdBytes);
            passwd = new String(plainTextPwdBytes, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | IllegalArgumentException | InvalidAlgorithmParameterException e) {
            e.printStackTrace(); // TODO: It's an error, don't hide & forget it ¬¬
            passwd = new String();
        }

        return passwd;
    }

    public void saveOdooClientParameters(String host, String dbname, int uid, String passwd) {
        SharedPreferences.Editor editor = mSettings.edit();
        editor.putInt("UserID", uid);
        editor.putString("Host", host);
        editor.putString("DBName", dbname);

        try {
            final byte[] cleartext = passwd.getBytes(StandardCharsets.UTF_8);

            KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_METHOD.split("/")[0]);
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();
            editor.putString("rn", Base64.encodeToString(secretKey.getEncoded(), Base64.NO_WRAP));

            final Cipher cipher = Cipher.getInstance(CIPHER_METHOD);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            editor.putString("iv", Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP));
            final String encPasswdBase64 = Base64.encodeToString(cipher.doFinal(cleartext), Base64.NO_WRAP);
            editor.putString("Pass", encPasswdBase64);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace(); // TODO: It's an error, don't hide & forget it ¬¬
        }

        editor.apply();
    }

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
            String passwd = getUserPassword();

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

        super.onCreate();
    }

}
