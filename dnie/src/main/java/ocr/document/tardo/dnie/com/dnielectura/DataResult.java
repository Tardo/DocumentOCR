package com.dnielectura;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;
import android.widget.Toast;
import com.dnielectura.jj2000.J2kStreamDecoder;
import de.tsenger.androsmex.mrtd.DG11;
import de.tsenger.androsmex.mrtd.DG13;
import de.tsenger.androsmex.mrtd.DG1_Dnie;
import de.tsenger.androsmex.mrtd.DG2;
import de.tsenger.androsmex.mrtd.DG7;
import java.io.ByteArrayInputStream;

public class DataResult extends Activity {
    private Bitmap loadedImage;
    private Bitmap loadedSignature;
    private DG1_Dnie m_dg1 = null;
    private DG11 m_dg11 = null;
    private DG13 m_dg13 = null;
    private DG2 m_dg2 = null;
    private DG7 m_dg7 = null;

    /* renamed from: com.dnielectura.DataResult$1 */
    class C00271 implements OnClickListener {
        C00271() {
        }

        public void onClick(View v) {
            DataResult.this.startActivity(new Intent(DataResult.this, DNIeLectura.class));
            DataResult.this.finish();
        }
    }

    /* renamed from: com.dnielectura.DataResult$2 */
    class C00282 implements OnClickListener {
        C00282() {
        }

        public void onClick(View v) {
            DataResult.this.startActivityForResult(new Intent(DataResult.this, DataConfiguration.class), 1);
        }
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(1);
        setContentView(C0041R.layout.data_result);
        Context myContext = this;
        Bundle extras = getIntent().getExtras();
        if (extras != null) {
            this.loadedImage = null;
            this.loadedSignature = null;
            byte[] m_dataDG1 = extras.getByteArray("DGP_DG1");
            byte[] m_dataDG2 = extras.getByteArray("DGP_DG2");
            byte[] m_dataDG7 = extras.getByteArray("DGP_DG7");
            byte[] m_dataDG11 = extras.getByteArray("DGP_DG11");
            byte[] m_dataDG13 = extras.getByteArray("DGP_DG13");
            if (m_dataDG1 != null) {
                try {
                    this.m_dg1 = new DG1_Dnie(m_dataDG1);
                } catch (Exception e) {
                    Toast.makeText(myContext, "Error en la lectura de DGs", 1).show();
                    return;
                }
            }
            if (m_dataDG2 != null) {
                this.m_dg2 = new DG2(m_dataDG2);
            }
            if (m_dataDG7 != null) {
                this.m_dg7 = new DG7(m_dataDG7);
            }
            if (m_dataDG11 != null) {
                this.m_dg11 = new DG11(m_dataDG11);
            }
            if (m_dataDG13 != null) {
                this.m_dg13 = new DG13(m_dataDG13);
            }
            if (m_dataDG11 == null) {
                try {
                    findViewById(C0041R.id.CITIZEN_data_tab_08_title).setVisibility(8);
                    findViewById(C0041R.id.CITIZEN_data_tab_08).setVisibility(8);
                    findViewById(C0041R.id.CITIZEN_data_tab_04_title).setVisibility(8);
                    findViewById(C0041R.id.CITIZEN_data_tab_04).setVisibility(8);
                    findViewById(C0041R.id.CITIZEN_data_tab_05_title).setVisibility(8);
                    findViewById(C0041R.id.CITIZEN_data_tab_05).setVisibility(8);
                    findViewById(C0041R.id.CITIZEN_data_tab_06_title).setVisibility(8);
                    findViewById(C0041R.id.CITIZEN_data_tab_06).setVisibility(8);
                } catch (Exception e2) {
                    Toast.makeText(myContext, "Error en la lectura de DGs", 1).show();
                    return;
                }
            }
            if (m_dataDG13 == null) {
                findViewById(C0041R.id.CITIZEN_data_tab_10_title).setVisibility(8);
                findViewById(C0041R.id.CITIZEN_data_tab_10).setVisibility(8);
            }
            try {
                if (this.m_dg1 != null) {
                    ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_01)).setText(this.m_dg1.getName());
                    ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_02)).setText(this.m_dg1.getSurname());
                    ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_03)).setText(this.m_dg1.getOptData() + " (val. " + this.m_dg1.getDateOfExpiry() + ")");
                    ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_07)).setText(this.m_dg1.getDateOfBirth());
                    ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_09)).setText(this.m_dg1.getNationality().toUpperCase());
                }
                try {
                    if (this.m_dg11 != null) {
                        ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_08)).setText(this.m_dg11.getBirthPlace().replace("<", " (") + ")");
                        ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_03)).setText(this.m_dg11.getPersonalNumber());
                        ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_04)).setText(this.m_dg11.getAddress(1));
                        ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_05)).setText(this.m_dg11.getAddress(3));
                        ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_06)).setText(this.m_dg11.getAddress(2));
                    }
                    try {
                        int i;
                        View view;
                        TableRow row;
                        int idx;
                        View viewText;
                        if (this.m_dg13 != null) {
                            ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_10)).setText(this.m_dg13.getFatherName() + " y " + this.m_dg13.getMotherName());
                            if (this.m_dg1.getDocType().compareTo("ID") == 0) {
                                ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_01)).setText(this.m_dg13.getName());
                                ((TextView) findViewById(C0041R.id.CITIZEN_data_tab_02)).setText(this.m_dg13.getSurName1() + " " + this.m_dg13.getSurName2());
                            }
                        }
                        ImageView ivFoto = (ImageView) findViewById(C0041R.id.CITIZEN_data_tab_00);
                        if (m_dataDG2 != null) {
                            try {
                                this.loadedImage = new J2kStreamDecoder().decode(new ByteArrayInputStream(this.m_dg2.getImageBytes()));
                            } catch (Exception e3) {
                                try {
                                    e3.printStackTrace();
                                } catch (Exception e4) {
                                    Toast.makeText(myContext, "Error en la lectura de DG-2", 1).show();
                                    return;
                                }
                            }
                        }
                        if (this.loadedImage != null) {
                            ivFoto.setImageBitmap(this.loadedImage);
                        } else {
                            ivFoto.setImageResource(C0041R.drawable.noface);
                        }
                        ImageView ivFirma = (ImageView) findViewById(C0041R.id.CITIZEN_data_tab_00_FIRMA);
                        if (m_dataDG7 != null) {
                            try {
                                this.loadedSignature = new J2kStreamDecoder().decode(new ByteArrayInputStream(this.m_dg7.getImageBytes()));
                            } catch (Exception e32) {
                                try {
                                    e32.printStackTrace();
                                } catch (Exception e5) {
                                    Toast.makeText(myContext, "Error en la lectura de DG-7", 1).show();
                                    return;
                                }
                            }
                        }
                        if (this.loadedSignature != null) {
                            ivFirma.setVisibility(0);
                            ivFirma.setImageBitmap(this.loadedSignature);
                        }
                        Typeface typeFace = Typeface.createFromAsset(getAssets(), "fonts/HelveticaNeue.ttf");
                        TableLayout miTabla = (TableLayout) findViewById(C0041R.id.data_table);
                        int j = miTabla.getChildCount();
                        for (i = 0; i < j; i++) {
                            view = miTabla.getChildAt(i);
                            if (view instanceof TableRow) {
                                row = (TableRow) view;
                                for (idx = 0; idx < row.getChildCount(); idx++) {
                                    viewText = row.getChildAt(idx);
                                    if (viewText instanceof TextView) {
                                        ((TextView) viewText).setTypeface(typeFace);
                                    }
                                }
                            }
                        }
                        miTabla = (TableLayout) findViewById(C0041R.id.data_table2);
                        j = miTabla.getChildCount();
                        for (i = 0; i < j; i++) {
                            view = miTabla.getChildAt(i);
                            if (view instanceof TableRow) {
                                row = (TableRow) view;
                                for (idx = 0; idx < row.getChildCount(); idx++) {
                                    viewText = row.getChildAt(idx);
                                    if (viewText instanceof TextView) {
                                        ((TextView) viewText).setTypeface(typeFace);
                                    }
                                }
                            }
                        }
                    } catch (Exception e6) {
                        Toast.makeText(myContext, "Error en la lectura de DG-13", 1).show();
                        return;
                    }
                } catch (Exception e7) {
                    Toast.makeText(myContext, "Error en la lectura de DG-11", 1).show();
                    return;
                }
            } catch (Exception e8) {
                Toast.makeText(myContext, "Error en la lectura de DG-1", 1).show();
                return;
            }
        }
        ((Button) findViewById(C0041R.id.butVolver)).setOnClickListener(new C00271());
        ((Button) findViewById(C0041R.id.butConfigurar)).setOnClickListener(new C00282());
    }
}
