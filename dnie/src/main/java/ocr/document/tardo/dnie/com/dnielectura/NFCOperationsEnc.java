package com.dnielectura;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcB;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.os.Process;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import custom.org.apache.harmony.security.fortress.PolicyUtils;
import de.tsenger.androsmex.data.CANSpecDO;
import de.tsenger.androsmex.data.CANSpecDOStore;
import de.tsenger.androsmex.mrtd.DG11;
import de.tsenger.androsmex.mrtd.DG13;
import de.tsenger.androsmex.mrtd.DG1_Dnie;
import de.tsenger.androsmex.mrtd.DG2;
import de.tsenger.androsmex.mrtd.DG7;
import de.tsenger.androsmex.mrtd.EF_COM;
import de.tsenger.androsmex.pace.PaceException;
import es.gob.jmulticard.jse.provider.DnieKeyStore;
import es.gob.jmulticard.jse.provider.DnieProvider;
import es.gob.jmulticard.jse.provider.MrtdKeyStoreImpl;
import java.security.Security;
import org.bouncycastle.asn1.eac.EACTags;

public class NFCOperationsEnc extends Activity {
    public static boolean m_readDg1;
    public static boolean m_readDg11;
    public static boolean m_readDg13;
    public static boolean m_readDg2;
    public static boolean m_readDg7;
    final Runnable cleanFragment = new C00302();
    private IsoDep exIsoDep;
    private NfcA exNfcA;
    private NfcB exNfcB;
    private boolean m_bRestart = false;
    private DG1_Dnie m_dg1;
    private DG11 m_dg11;
    private DG13 m_dg13;
    private DG2 m_dg2;
    private DG7 m_dg7;
    private EF_COM m_efcom;
    private boolean m_existDg1;
    private boolean m_existDg11;
    private boolean m_existDg13;
    private boolean m_existDg2;
    private boolean m_existDg7;
    private Context myContext;
    final Handler myHandler = new Handler();
    private ProgressDialog progressDlg;
    private Tag tagFromIntent = null;
    private String textoProcessDlg;
    private String textoResultPage;
    final Runnable updateStatus = new C00291();

    /* renamed from: com.dnielectura.NFCOperationsEnc$1 */
    class C00291 implements Runnable {
        C00291() {
        }

        public void run() {
            NFCOperationsEnc.this.progressDlg.setMessage(NFCOperationsEnc.this.textoProcessDlg);
        }
    }

    /* renamed from: com.dnielectura.NFCOperationsEnc$2 */
    class C00302 implements Runnable {
        C00302() {
        }

        public void run() {
            NFCOperationsEnc.this.findViewById(C0041R.id.resultimg).setVisibility(4);
            NFCOperationsEnc.this.findViewById(C0041R.id.tituloresultado).setVisibility(4);
            NFCOperationsEnc.this.findViewById(C0041R.id.textoresultado).setVisibility(4);
        }
    }

    /* renamed from: com.dnielectura.NFCOperationsEnc$3 */
    class C00313 implements OnClickListener {
        C00313() {
        }

        public void onClick(View v) {
            NFCOperationsEnc.this.startActivity(new Intent(NFCOperationsEnc.this, DNIeCanSelection.class));
        }
    }

    /* renamed from: com.dnielectura.NFCOperationsEnc$4 */
    class C00324 implements OnClickListener {
        C00324() {
        }

        public void onClick(View v) {
            NFCOperationsEnc.this.startActivityForResult(new Intent(NFCOperationsEnc.this, DataConfiguration.class), 1);
        }
    }

    public class MyTaskDNIe extends AsyncTask<Void, Integer, Void> {
        private boolean bCompleted = false;

        protected void onPreExecute() {
            this.bCompleted = false;
            NFCOperationsEnc.this.myHandler.post(NFCOperationsEnc.this.cleanFragment);
            NFCOperationsEnc.this.progressDlg.setIndeterminate(true);
            NFCOperationsEnc.this.progressDlg.setCancelable(false);
            NFCOperationsEnc.this.progressDlg.setTitle("DNIe version 3.0");
            NFCOperationsEnc.this.progressDlg.setMessage("Leyendo DNIe...");
            NFCOperationsEnc.this.progressDlg.show();
        }

        protected Void doInBackground(Void... arg0) {
            try {
                NFCOperationsEnc.this.CargarDGs();
                this.bCompleted = true;
            } catch (PaceException e) {
                NFCOperationsEnc.this.textoResultPage = e.getMessage();
            } catch (Exception e2) {
                NFCOperationsEnc.this.textoResultPage = "Ocurrió un error durante la lectura de los DGs.";
                if (e2.getMessage() != null) {
                    if (e2.getMessage().contains("lost")) {
                        NFCOperationsEnc.this.textoResultPage = "Error de comunicación. Se ha perdido la conexión con el DNIe.";
                    } else {
                        NFCOperationsEnc.this.textoResultPage = e2.getMessage();
                    }
                }
            }
            return null;
        }

        protected void onPostExecute(Void result) {
            if (this.bCompleted) {
                NFCOperationsEnc.this.m_bRestart = false;
                Bundle b = new Bundle();
                if (NFCOperationsEnc.this.m_dg1 != null) {
                    b.putByteArray("DGP_DG1", NFCOperationsEnc.this.m_dg1.getBytes());
                }
                if (NFCOperationsEnc.this.m_dg2 != null) {
                    b.putByteArray("DGP_DG2", NFCOperationsEnc.this.m_dg2.getBytes());
                }
                if (NFCOperationsEnc.this.m_dg7 != null) {
                    b.putByteArray("DGP_DG7", NFCOperationsEnc.this.m_dg7.getBytes());
                }
                if (NFCOperationsEnc.this.m_dg11 != null) {
                    b.putByteArray("DGP_DG11", NFCOperationsEnc.this.m_dg11.getBytes());
                }
                if (NFCOperationsEnc.this.m_dg13 != null) {
                    b.putByteArray("DGP_DG13", NFCOperationsEnc.this.m_dg13.getBytes());
                }
                Intent myResultIntent = new Intent(NFCOperationsEnc.this, DataResult.class);
                myResultIntent.putExtras(b);
                NFCOperationsEnc.this.startActivity(myResultIntent);
                NFCOperationsEnc.this.finish();
                return;
            }
            NFCOperationsEnc.this.progressDlg.dismiss();
            NFCOperationsEnc.this.HandleError(NFCOperationsEnc.this.textoResultPage);
        }
    }

    public void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        if (((MyAppDNIELECTURA) getApplicationContext()).isStarted()) {
            requestWindowFeature(1);
            setContentView(C0041R.layout.nfcact2);
            this.myContext = this;
            this.tagFromIntent = null;
            this.progressDlg = new ProgressDialog(this);
            resolveIntent(getIntent());
            this.m_dg1 = null;
            this.m_dg2 = null;
            this.m_dg7 = null;
            this.m_dg11 = null;
            this.m_dg13 = null;
            if (this.tagFromIntent != null) {
                if (!((this.exNfcA == null && this.exNfcB == null) || this.exIsoDep == null)) {
                    this.exIsoDep.setTimeout(3000);
                    new MyTaskDNIe().execute(new Void[0]);
                }
                Typeface fontType = Typeface.createFromAsset(this.myContext.getAssets(), "fonts/HelveticaNeue.ttf");
                ((TextView) findViewById(C0041R.id.textoresultado)).setTypeface(fontType);
                ((TextView) findViewById(C0041R.id.tituloresultado)).setTypeface(fontType);
                ((Button) findViewById(C0041R.id.butVolver)).setOnClickListener(new C00313());
                ((Button) findViewById(C0041R.id.butConfigurar)).setOnClickListener(new C00324());
                return;
            }
            return;
        }
        Toast.makeText(getApplicationContext(), "Esta aplicación había quedado abierta irregularmente. Salimos.\n", 1).show();
        getApplicationContext().getPackageManager().setComponentEnabledSetting(new ComponentName(getApplicationContext(), NFCOperationsEnc.class), 2, 0);
        Process.killProcess(Process.myPid());
        System.exit(0);
    }

    protected void onStart() {
        super.onStart();
        getApplicationContext().getPackageManager().setComponentEnabledSetting(new ComponentName(getApplicationContext(), NFCOperationsEnc.class), 2, 1);
        if (!this.m_bRestart) {
            return;
        }
        if (!((MyAppDNIELECTURA) getApplicationContext()).isStarted()) {
            Toast.makeText(getApplicationContext(), "Esta aplicación había quedado abierta irregularmente. Salimos.\n", 0).show();
            Process.killProcess(Process.myPid());
            System.exit(0);
        } else if (this.tagFromIntent == null) {
        } else {
            if ((this.exNfcA != null || this.exNfcB != null) && this.exIsoDep != null) {
                this.exIsoDep.setTimeout(3000);
                new MyTaskDNIe().execute(new Void[0]);
            }
        }
    }

    protected void onStop() {
        super.onStop();
        getApplicationContext().getPackageManager().setComponentEnabledSetting(new ComponentName(getApplicationContext(), NFCOperationsEnc.class), 2, 1);
    }

    void resolveIntent(Intent intent) {
        this.tagFromIntent = (Tag) intent.getParcelableExtra("android.nfc.extra.TAG");
        if (this.tagFromIntent != null) {
            this.exNfcA = NfcA.get(this.tagFromIntent);
            this.exNfcB = NfcB.get(this.tagFromIntent);
            this.exIsoDep = IsoDep.get(this.tagFromIntent);
        }
    }

    public void onNewIntent(Intent intent) {
        setIntent(intent);
        resolveIntent(intent);
        this.m_bRestart = true;
    }

    private void HandleError(String strError) {
        findViewById(C0041R.id.resultimg).setVisibility(0);
        findViewById(C0041R.id.tituloresultado).setVisibility(0);
        TextView txt = (TextView) findViewById(C0041R.id.textoresultado);
        txt.setText(strError);
        txt.setVisibility(0);
    }

    public boolean CargarDGs() throws Exception {
        this.textoProcessDlg = "Leyendo datos...";
        this.myHandler.post(this.updateStatus);
        CANSpecDOStore cansDO = new CANSpecDOStore(this);
        CANSpecDO canDnie = ((MyAppDNIELECTURA) getApplicationContext()).getCAN();
        System.setProperty("es.gob.jmulticard.fastmode", PolicyUtils.TRUE);
        DnieProvider p = new DnieProvider();
        p.setProviderTag(this.tagFromIntent);
        String can6digitos = canDnie.getCanNumber();
        while (can6digitos.length() < 6) {
            can6digitos = "0" + can6digitos;
        }
        p.setProviderCan(can6digitos);
        Security.insertProviderAt(p, 1);
        DnieKeyStore m_ksUserMrtd = new DnieKeyStore(new MrtdKeyStoreImpl(), p, "MRTD");
        m_ksUserMrtd.load(null, null);
        readUserConfiguration();
        try {
            this.m_efcom = m_ksUserMrtd.getEFCOM();
            byte[] tagList = this.m_efcom.getTagList();
            for (byte b : tagList) {
                switch (b) {
                    case EACTags.APPLICATION_TEMPLATE /*97*/:
                        this.m_existDg1 = true;
                        break;
                    case (byte) 103:
                        this.m_existDg7 = true;
                        break;
                    case (byte) 107:
                        this.m_existDg11 = true;
                        break;
                    case (byte) 109:
                        this.m_existDg13 = true;
                        break;
                    case (byte) 117:
                        this.m_existDg2 = true;
                        break;
                    default:
                        break;
                }
            }
            try {
                if (m_readDg1 && this.m_existDg1) {
                    this.m_dg1 = m_ksUserMrtd.getDatagroup1();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                if (m_readDg11 && this.m_existDg11) {
                    this.m_dg11 = m_ksUserMrtd.getDatagroup11();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            if (canDnie.getUserNif().length() == 0) {
                String docNumber;
                String certSubject = this.m_dg1.getName() + " " + this.m_dg1.getSurname();
                if (this.m_dg11 == null) {
                    docNumber = this.m_dg1.getDocNumber();
                } else {
                    docNumber = this.m_dg11.getPersonalNumber();
                }
                CANSpecDO newCan = new CANSpecDO(canDnie.getCanNumber(), certSubject, docNumber);
                cansDO.delete(canDnie);
                cansDO.save(newCan);
            }
            if (m_readDg2 && this.m_existDg2) {
                this.textoProcessDlg = "Cargando foto...";
                this.myHandler.post(this.updateStatus);
                this.m_dg2 = m_ksUserMrtd.getDatagroup2();
            }
            if (m_readDg7 && this.m_existDg7) {
                this.textoProcessDlg = "Cargando firma...";
                this.myHandler.post(this.updateStatus);
                this.m_dg7 = m_ksUserMrtd.getDatagroup7();
            }
            if (this.m_existDg13 && (m_readDg13 || this.m_dg1.getDocType().compareTo("ID") == 0)) {
                this.m_dg13 = m_ksUserMrtd.getDatagroup13();
            }
            return true;
        } catch (Exception e22) {
            e22.printStackTrace();
            throw e22;
        } catch (Exception e222) {
            e222.printStackTrace();
            throw e222;
        } catch (Exception e2222) {
            e2222.printStackTrace();
            throw e2222;
        } catch (Exception e22222) {
            e22222.printStackTrace();
            throw e22222;
        } catch (Exception e222222) {
            this.textoResultPage = "Ocurrió un error durante la lectura de los DGs.\n";
            if (e222222.getMessage() != null) {
                if (e222222.getMessage().contains("Tag was lost")) {
                    this.textoResultPage += "Se perdió la conexión inalámbrica con el DNI electrónico.";
                } else {
                    this.textoResultPage += e222222.getMessage();
                }
            }
            throw new Exception(this.textoResultPage);
        }
    }

    void readUserConfiguration() {
        SharedPreferences sharedPreferences = getApplicationContext().getSharedPreferences("com.sp.main_preferences", 0);
        m_readDg1 = true;
        m_readDg2 = sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG2, false);
        m_readDg7 = sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG7, false);
        m_readDg11 = sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG11, true);
        m_readDg13 = sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG13, true);
    }
}
