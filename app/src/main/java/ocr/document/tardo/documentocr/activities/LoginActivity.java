/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.accounts.AccountAuthenticatorActivity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.eiqui.odoojson_rpc.JSONRPCClientOdoo;
import com.eiqui.odoojson_rpc.exceptions.OdooLoginException;
import com.eiqui.odoojson_rpc.exceptions.OdooSearchException;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import ocr.document.tardo.documentocr.AppMain;
import ocr.document.tardo.documentocr.R;
import ocr.document.tardo.documentocr.utils.Constants;

public class LoginActivity extends AccountAuthenticatorActivity implements OnClickListener {

    public static String PARAM_LOGOUT = "logout";
    private EditText mEditHost;
    private EditText mEditDBName;
    private EditText mEditLogin;
    private EditText mEditPass;
    private TextView mTextError;
    private Button mBtnLoginIn;
    private ProgressBar mProgressBar;
    private ImageView mLogo;
    private SharedPreferences mSettings;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        mSettings = getSharedPreferences(Constants.SHARED_PREFS_USER_INFO, Context.MODE_PRIVATE);

        mEditHost = findViewById(R.id.editHost);
        mEditDBName = findViewById(R.id.editDBName);
        mEditLogin = findViewById(R.id.editLogin);
        mEditPass = findViewById(R.id.editPassword);
        mBtnLoginIn = findViewById(R.id.btnLogin);
        mProgressBar = findViewById(R.id.progressBar);
        mLogo = findViewById(R.id.logoApp);
        mTextError = findViewById(R.id.txtError);

        mLogo.setAlpha(0.0f);
        mLogo.setTranslationY(-100);
        mLogo.animate().alpha(1.0f).translationY(0).setStartDelay(250);

        mBtnLoginIn.setAlpha(0.0f);
        mBtnLoginIn.setTranslationY(100);
        mBtnLoginIn.animate().alpha(1.0f).translationY(0).setStartDelay(250);

        if (getIntent().getBooleanExtra(PARAM_LOGOUT, Boolean.FALSE))
            logout();

        mEditHost.setText(mSettings.getString("Host", ""));
        mEditDBName.setText(mSettings.getString("DBName", ""));

        mBtnLoginIn.setOnClickListener(this);

        // Ignorar login si ya se logeo correctamente
        if (mSettings.getInt("UserID", -1) > 0)
            initApp();
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.btnLogin)
        {
            new LoginTask().execute(
                    mEditHost.getText().toString(),
                    mEditDBName.getText().toString(), mEditLogin.getText().toString(),
                    mEditPass.getText().toString());
            mTextError.setVisibility(View.INVISIBLE);
            hideControls(Boolean.TRUE);
        }
    }

    private void logout() {
        SharedPreferences.Editor editor = mSettings.edit();
        editor.remove("UserID");
        editor.remove("lastTaskID");
        editor.remove("lastIssueID");
        editor.remove("lastMessageID");
        editor.remove("Pass");
        editor.commit();
    }

    private void initApp() {
        String passwd = new String();
        try {
            byte[] encrypedPwdBytes = Base64.decode(mSettings.getString("Pass", ""), Base64.NO_WRAP);
            DESKeySpec keySpec = new DESKeySpec(mSettings.getString("rn", "").getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey key = keyFactory.generateSecret(keySpec);
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] plainTextPwdBytes = (cipher.doFinal(encrypedPwdBytes));
            passwd = new String(plainTextPwdBytes, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }

        try {
            ((AppMain)getApplication()).startOdooClient(mSettings.getString("Host",""),
                    mSettings.getString("DBName",""),
                    mSettings.getInt("UserID",-1), passwd);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            showErrorMessage(getResources().getString(R.string.init_app_error));
        }

        new CheckHotelL10NTask().execute();

        startActivity(new Intent(this, ReadModeActivity.class));
        finish();
    }

    private void hideControls(Boolean state) {
        mEditLogin.setEnabled(!state);
        mEditPass.setEnabled(!state);
        mBtnLoginIn.setVisibility(state==Boolean.TRUE?View.GONE:View.VISIBLE);
        mProgressBar.setVisibility(state==Boolean.TRUE?View.VISIBLE:View.GONE);

    }

    private void showErrorMessage(String text) {
        mTextError.setAlpha(0.0f);
        mTextError.setVisibility(View.VISIBLE);
        mTextError.animate().alpha(1.0f);
        mTextError.setText(text);
        hideControls(Boolean.FALSE);
    }


    private class LoginTask extends AsyncTask<String, Void, Boolean> {
        private Exception mException;
        private Integer mUID;


        protected Boolean doInBackground(String... params) {
            mException = null;
            try {
                ((AppMain)getApplication()).startOdooClient(params[0], params[1], -1, "");
                JSONRPCClientOdoo OdooClient = ((AppMain)getApplication()).OdooClient();
                mUID = OdooClient.loginIn(params[2], params[3]);
                return (mUID > 0);
            } catch (OdooLoginException e) {
                mException = e;
            } catch (MalformedURLException e) {
                mException = e;
                e.printStackTrace();
            }
            return Boolean.FALSE;
        }

        protected void onPostExecute(Boolean res) {
            if (res) {
                SharedPreferences.Editor editor = mSettings.edit();
                editor.putInt("UserID", mUID);
                editor.putString("Host", mEditHost.getText().toString());
                editor.putString("DBName", mEditDBName.getText().toString());

                try {
                    byte[] cleartext = mEditPass.getText().toString().getBytes("UTF8");
                    DESKeySpec keySpec = new DESKeySpec(mSettings.getString("rn", "").getBytes());
                    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
                    SecretKey key = keyFactory.generateSecret(keySpec);
                    Cipher cipher = Cipher.getInstance("DES");
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                    final String encPasswdBase64 = Base64.encodeToString(cipher.doFinal(cleartext), Base64.NO_WRAP);
                    Log.v("MITAA", encPasswdBase64);
                    editor.putString("Pass", encPasswdBase64);
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                }

                editor.commit();

                initApp();
            }
            else {
               showErrorMessage(
                       (mException != null)?mException.getMessage():getResources().getString(R.string.login_invalid));
            }
        }
    }

    private class CheckHotelL10NTask extends AsyncTask<String, Void, Boolean> {
        private Exception mException;
        private Boolean mHasHotelL10N = false;


        protected Boolean doInBackground(String... params) {
            mException = null;
            final JSONRPCClientOdoo OdooClient = ((AppMain)getApplication()).OdooClient();
            try {
                mHasHotelL10N = OdooClient.callCount(
                        "ir.module.module",
                        "[['state', '=', 'installed'], ['name', '=', 'hotel_l10n_es']]") > 0;
            } catch (OdooSearchException e) {
                mException = e;
            }
            return Boolean.TRUE;
        }

        protected void onPostExecute(Boolean res) {
            if (res) {
                SharedPreferences.Editor editor = mSettings.edit();
                editor.putBoolean("HasHotelL10N", mHasHotelL10N);
                editor.commit();
            }
            else {
                showErrorMessage(
                        (mException != null)?mException.getMessage():getResources().getString(R.string.login_invalid));
            }
        }
    }

}