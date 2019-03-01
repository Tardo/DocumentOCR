package com.dnielectura;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.TextView;

public class DataConfiguration extends Activity {
    private Context myContext;
    private SharedPreferences sharedPreferences;

    /* renamed from: com.dnielectura.DataConfiguration$1 */
    class C00181 implements OnCheckedChangeListener {
        C00181() {
        }

        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
            Editor editor = DataConfiguration.this.sharedPreferences.edit();
            editor.putBoolean(DNIeLectura.SETTING_READ_DG1, isChecked);
            editor.commit();
        }
    }

    /* renamed from: com.dnielectura.DataConfiguration$2 */
    class C00192 implements OnCheckedChangeListener {
        C00192() {
        }

        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
            Editor editor = DataConfiguration.this.sharedPreferences.edit();
            editor.putBoolean(DNIeLectura.SETTING_READ_DG11, isChecked);
            editor.commit();
        }
    }

    /* renamed from: com.dnielectura.DataConfiguration$3 */
    class C00203 implements OnCheckedChangeListener {
        C00203() {
        }

        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
            Editor editor = DataConfiguration.this.sharedPreferences.edit();
            editor.putBoolean(DNIeLectura.SETTING_READ_DG13, isChecked);
            editor.commit();
        }
    }

    /* renamed from: com.dnielectura.DataConfiguration$4 */
    class C00214 implements OnCheckedChangeListener {
        C00214() {
        }

        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
            Editor editor = DataConfiguration.this.sharedPreferences.edit();
            editor.putBoolean(DNIeLectura.SETTING_READ_DG2, isChecked);
            editor.commit();
        }
    }

    /* renamed from: com.dnielectura.DataConfiguration$5 */
    class C00225 implements OnCheckedChangeListener {
        C00225() {
        }

        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
            Editor editor = DataConfiguration.this.sharedPreferences.edit();
            editor.putBoolean(DNIeLectura.SETTING_READ_DG7, isChecked);
            editor.commit();
        }
    }

    /* renamed from: com.dnielectura.DataConfiguration$6 */
    class C00236 implements OnClickListener {
        C00236() {
        }

        public void onClick(View v) {
            DataConfiguration.this.onBackPressed();
        }
    }

    /* renamed from: com.dnielectura.DataConfiguration$7 */
    class C00247 implements OnClickListener {
        C00247() {
        }

        public void onClick(View v) {
            DataConfiguration.this.startActivity(new Intent(DataConfiguration.this, DNIeCanSelection.class));
        }
    }

    void updateUserData() {
        this.sharedPreferences = getApplicationContext().getSharedPreferences("com.sp.main_preferences", 0);
        ((CheckBox) findViewById(C0041R.id.checkBoxDG1)).setChecked(this.sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG1, true));
        ((CheckBox) findViewById(C0041R.id.checkBoxDG2)).setChecked(this.sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG2, true));
        ((CheckBox) findViewById(C0041R.id.checkBoxDG7)).setChecked(this.sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG7, false));
        ((CheckBox) findViewById(C0041R.id.checkBoxDG11)).setChecked(this.sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG11, true));
        ((CheckBox) findViewById(C0041R.id.checkBoxDG13)).setChecked(this.sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG13, true));
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(1);
        setContentView(C0041R.layout.data_configuration);
        this.myContext = this;
        updateUserData();
        Typeface typeFace = Typeface.createFromAsset(this.myContext.getAssets(), "fonts/HelveticaNeue.ttf");
        ((TextView) findViewById(C0041R.id.configuration_description)).setTypeface(typeFace);
        ((CheckBox) findViewById(C0041R.id.checkBoxDG1)).setTypeface(typeFace);
        ((CheckBox) findViewById(C0041R.id.checkBoxDG2)).setTypeface(typeFace);
        ((CheckBox) findViewById(C0041R.id.checkBoxDG7)).setTypeface(typeFace);
        ((CheckBox) findViewById(C0041R.id.checkBoxDG11)).setTypeface(typeFace);
        ((CheckBox) findViewById(C0041R.id.checkBoxDG13)).setTypeface(typeFace);
        ((CheckBox) findViewById(C0041R.id.checkBoxDG1)).setOnCheckedChangeListener(new C00181());
        ((CheckBox) findViewById(C0041R.id.checkBoxDG11)).setOnCheckedChangeListener(new C00192());
        ((CheckBox) findViewById(C0041R.id.checkBoxDG13)).setOnCheckedChangeListener(new C00203());
        ((CheckBox) findViewById(C0041R.id.checkBoxDG2)).setOnCheckedChangeListener(new C00214());
        ((CheckBox) findViewById(C0041R.id.checkBoxDG7)).setOnCheckedChangeListener(new C00225());
        ((Button) findViewById(C0041R.id.butDataVolver)).setOnClickListener(new C00236());
        ((Button) findViewById(C0041R.id.butDataLeer)).setOnClickListener(new C00247());
    }
}
