/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.Manifest;
import android.accounts.AccountAuthenticatorActivity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.TextInputEditText;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.eiqui.odoojson_rpc.JSONRPCClientOdoo;
import com.eiqui.odoojson_rpc.exceptions.OdooLoginException;
import com.eiqui.odoojson_rpc.exceptions.OdooSearchException;
import com.googlecode.tesseract.android.TessBaseAPI;

import org.json.JSONArray;
import org.json.JSONException;

import java.net.MalformedURLException;
import java.util.ArrayList;

import ocr.document.tardo.documentocr.AppMain;
import ocr.document.tardo.documentocr.R;
import ocr.document.tardo.documentocr.utils.Constants;

import static ocr.document.tardo.documentocr.AppMain.DATA_PATH;
import static ocr.document.tardo.documentocr.AppMain.TESS_LANG;

public class LoginActivity extends AccountAuthenticatorActivity implements OnClickListener, View.OnFocusChangeListener {

    private final int REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE = 1;

    public static String PARAM_LOGOUT = "logout";
    public TextInputEditText mEditHost;
    public AutoCompleteTextView mEditDBName;
    public TextInputEditText mEditLogin;
    public TextInputEditText mEditPass;
    private TextView mTextError;
    private Button mBtnLoginIn;
    private ProgressBar mProgressBar;
    public SharedPreferences mSettings;

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
        mTextError = findViewById(R.id.txtError);

        final ImageView Logo = findViewById(R.id.logoApp);
        Logo.setAlpha(0.0f);
        Logo.setTranslationY(-100);
        Logo.animate().alpha(1.0f).translationY(0).setStartDelay(250);

        mBtnLoginIn.setAlpha(0.0f);
        mBtnLoginIn.setTranslationY(100);
        mBtnLoginIn.animate().alpha(1.0f).translationY(0).setStartDelay(250);

        if (getIntent().getBooleanExtra(PARAM_LOGOUT, Boolean.FALSE))
            logout();

        mEditHost.setText(mSettings.getString("Host", ""));
        mEditDBName.setText(mSettings.getString("DBName", ""));

        mEditHost.setOnFocusChangeListener(this);
        mBtnLoginIn.setOnClickListener(this);
        mEditDBName.setOnClickListener(this);

        if (mEditHost.getText() != null) {
            new GetDBTask().execute(mEditHost.getText().toString());
        }

        // Comprobar que la app tiene permisos suficientes para funcionar correctamente
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                    REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE);
        }  else {
            initTesseract();
            // Ignorar login si ya se logeo correctamente
            if (mSettings.getInt("UserID", -1) > 0)
                initApp();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (requestCode == REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                initTesseract();
                // Ignorar login si ya se logeo correctamente
                if (mSettings.getInt("UserID", -1) > 0)
                    initApp();
                Toast.makeText(LoginActivity.this, "Permission Granted!", Toast.LENGTH_SHORT).show();
            } else {
                // TODO: No ser tan duro y mostrar algun mensaje de error
                android.os.Process.killProcess(android.os.Process.myPid());
                System.exit(0);
            }
        }
    }


    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.btnLogin && mEditHost.getText() != null && mEditLogin.getText() != null && mEditPass.getText() != null)
        {
            new LoginTask().execute(
                    mEditHost.getText().toString(),
                    mEditDBName.getText().toString(),
                    mEditLogin.getText().toString(),
                    mEditPass.getText().toString());
            mTextError.setVisibility(View.INVISIBLE);
            hideControls(Boolean.TRUE);
        } else if (v.getId() == R.id.editDBName)
        {
            mEditDBName.showDropDown();
        }
    }

    @Override
    public void onFocusChange(View v, boolean b) {
        if (!b && mEditHost.getText() != null) {
            new GetDBTask().execute(mEditHost.getText().toString());
        }
    }

    private void initTesseract() {
        TessBaseAPI tessApi = ((AppMain)getApplication()).getTessApi();
        tessApi.init(DATA_PATH, TESS_LANG);
        tessApi.setVariable("load_system_dawg", "F");
        tessApi.setVariable("load_freq_dawg", "F");
        tessApi.setVariable("load_unambig_dawg", "F");
        tessApi.setVariable("load_number_dawg", "F");
        tessApi.setVariable("load_fixed_length_dawgs", "F");
        tessApi.setVariable("load_bigram_dawg", "F");
        tessApi.setVariable("wordrec_enable_assoc", "F");
        tessApi.setVariable("tessedit_char_whitelist", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<");
    }

    private void logout() {
        SharedPreferences.Editor editor = mSettings.edit();
        editor.remove("UserID");
        editor.remove("lastTaskID");
        editor.remove("lastIssueID");
        editor.remove("lastMessageID");
        editor.remove("Pass");
        editor.apply();
    }

    private void initApp() {
        hideControls(Boolean.TRUE);
        String passwd = ((AppMain)getApplication()).getUserPassword();
        if (!passwd.isEmpty()) {
            try {
                ((AppMain) getApplication()).startOdooClient(mSettings.getString("Host", ""),
                        mSettings.getString("DBName", ""),
                        mSettings.getInt("UserID", -1), passwd);
            } catch (MalformedURLException e) {
                e.printStackTrace();
                showErrorMessage(getResources().getString(R.string.init_app_error));
                return;
            }
        }

        // Init
        SharedPreferences.Editor editor = mSettings.edit();
        // FIXME: Hardcoded value to enable support with hootel l10n modules.
        // This will break the usage with vanilla Odoo
        editor.putBoolean("HasHotelL10N", Boolean.TRUE);
        editor.apply();
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
            if (res && mEditHost.getText() != null && mEditPass.getText() != null) {
                ((AppMain)getApplication()).saveOdooClientParameters(
                        mEditHost.getText().toString(),
                        mEditDBName.getText().toString(),
                        mUID,
                        mEditPass.getText().toString());
                initApp();
            }
            else {
                showErrorMessage(
                       (mException != null)?mException.getMessage():getResources().getString(R.string.login_invalid));
            }
        }
    }

    private class GetDBTask extends AsyncTask<String, Void, Boolean> {

        private JSONArray mDBList = new JSONArray();

        protected Boolean doInBackground(String... params) {
            final JSONRPCClientOdoo OdooClient;
            try {
                OdooClient = new JSONRPCClientOdoo(params[0]);
                mDBList = OdooClient.getDBList();
                return Boolean.TRUE;
            } catch (OdooSearchException | MalformedURLException e) {
                e.printStackTrace(); // TODO: It's an error, don't hide & forget it ¬¬
            }
            return Boolean.FALSE;
        }

        protected void onPostExecute(Boolean res) {
            ArrayList<String> list = new ArrayList<>();
            if (null != mDBList) {
                int len = mDBList.length();
                for (int i = 0; i < len; ++i) {
                    try {
                        list.add(mDBList.get(i).toString());
                    } catch (JSONException e) {
                        break;
                    }
                }
            }
            ArrayAdapter<String> adapter = new ArrayAdapter<>(LoginActivity.this,
                    android.R.layout.simple_dropdown_item_1line, list);
            mEditDBName.setAdapter(adapter);

            if (list.size() > 0 && mEditDBName.getText().length() == 0) {
                mEditDBName.setText(list.get(0));
            }
        }
    }

}