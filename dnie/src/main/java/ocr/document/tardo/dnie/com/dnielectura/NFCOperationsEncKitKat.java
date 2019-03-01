package com.dnielectura;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog.Builder;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.ReaderCallback;
import android.nfc.Tag;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
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
import de.tsenger.androsmex.pace.PaceException;
import es.gob.jmulticard.jse.provider.DnieKeyStore;
import es.gob.jmulticard.jse.provider.DnieProvider;
import es.gob.jmulticard.jse.provider.MrtdKeyStoreImpl;
import java.security.Security;
import org.bouncycastle.asn1.eac.EACTags;

@SuppressLint({"NewApi"})
public class NFCOperationsEncKitKat extends Activity implements ReaderCallback {
    public static boolean m_readDg1;
    public static boolean m_readDg11;
    public static boolean m_readDg13;
    public static boolean m_readDg2;
    public static boolean m_readDg7;
    private static NfcAdapter myNfcAdapter = null;
    final Runnable askForEnablingNFC = new C00384();
    final Runnable askForRead = new C00342();
    private CANSpecDO canDnie;
    private CANSpecDOStore cansDO;
    Typeface fontType;
    private boolean mForzamosReinicio = true;
    private DG1_Dnie m_dg1;
    private DG11 m_dg11;
    private DG13 m_dg13;
    private DG2 m_dg2;
    private DG7 m_dg7;
    private boolean m_existDg1;
    private boolean m_existDg11;
    private boolean m_existDg13;
    private boolean m_existDg2;
    private boolean m_existDg7;
    private DnieKeyStore m_ksUserMrtd = null;
    private Activity myActivity;
    private Context myContext;
    final Handler myHandler = new Handler();
    final Runnable newRead = new C00353();
    private ProgressDialog progressBar;
    private boolean readerModeON = false;
    private Tag tagFromIntent = null;
    private String textoProcessDlg;
    private String textoResultPage;
    final Runnable updateStatus = new C00331();

    /* renamed from: com.dnielectura.NFCOperationsEncKitKat$1 */
    class C00331 implements Runnable {
        C00331() {
        }

        public void run() {
            NFCOperationsEncKitKat.this.progressBar.setMessage(NFCOperationsEncKitKat.this.textoProcessDlg);
            if (!NFCOperationsEncKitKat.this.progressBar.isShowing()) {
                NFCOperationsEncKitKat.this.progressBar.show();
            }
        }
    }

    /* renamed from: com.dnielectura.NFCOperationsEncKitKat$2 */
    class C00342 implements Runnable {
        C00342() {
        }

        public void run() {
            NFCOperationsEncKitKat.this.textoResultPage = "";
            ((TextView) NFCOperationsEncKitKat.this.findViewById(C0041R.id.result1)).setText(C0041R.string.op_reinit);
            NFCOperationsEncKitKat.this.findViewById(C0041R.id.result1).setVisibility(0);
            ((ImageView) NFCOperationsEncKitKat.this.findViewById(C0041R.id.resultimg)).setImageResource(C0041R.drawable.boton_aproxdnie);
            NFCOperationsEncKitKat.this.findViewById(C0041R.id.resultimg).setVisibility(0);
            NFCOperationsEncKitKat.this.findViewById(C0041R.id.resultinfo).setVisibility(4);
        }
    }

    /* renamed from: com.dnielectura.NFCOperationsEncKitKat$3 */
    class C00353 implements Runnable {
        C00353() {
        }

        public void run() {
            NFCOperationsEncKitKat.this.textoResultPage = "";
            ((TextView) NFCOperationsEncKitKat.this.findViewById(C0041R.id.result1)).setText(C0041R.string.process_msg_lectura);
            NFCOperationsEncKitKat.this.findViewById(C0041R.id.result1).setVisibility(0);
            ((ImageView) NFCOperationsEncKitKat.this.findViewById(C0041R.id.resultimg)).setImageResource(C0041R.drawable.boton_aproxdnie);
            NFCOperationsEncKitKat.this.findViewById(C0041R.id.resultimg).setVisibility(0);
            NFCOperationsEncKitKat.this.findViewById(C0041R.id.resultinfo).setVisibility(4);
        }
    }

    /* renamed from: com.dnielectura.NFCOperationsEncKitKat$4 */
    class C00384 implements Runnable {

        /* renamed from: com.dnielectura.NFCOperationsEncKitKat$4$1 */
        class C00361 implements OnClickListener {
            C00361() {
            }

            public void onClick(DialogInterface dialog, int id) {
                NFCOperationsEncKitKat.this.startActivity(new Intent("android.settings.WIRELESS_SETTINGS"));
            }
        }

        /* renamed from: com.dnielectura.NFCOperationsEncKitKat$4$2 */
        class C00372 implements OnClickListener {
            C00372() {
            }

            public void onClick(DialogInterface dialog, int id) {
                dialog.cancel();
                NFCOperationsEncKitKat.this.onBackPressed();
                NFCOperationsEncKitKat.this.finish();
            }
        }

        C00384() {
        }

        public void run() {
            Builder alertDialogBuilder = new Builder(NFCOperationsEncKitKat.this.myContext);
            alertDialogBuilder.setMessage(NFCOperationsEncKitKat.this.getString(C0041R.string.nfc_disabled)).setCancelable(false).setPositiveButton(NFCOperationsEncKitKat.this.getString(C0041R.string.nfc_configuration), new C00361());
            alertDialogBuilder.setNegativeButton(NFCOperationsEncKitKat.this.getString(C0041R.string.psswd_dialog_cancel), new C00372());
            alertDialogBuilder.create().show();
        }
    }

    /* renamed from: com.dnielectura.NFCOperationsEncKitKat$5 */
    class C00395 implements View.OnClickListener {
        C00395() {
        }

        public void onClick(View v) {
            NFCOperationsEncKitKat.this.onBackPressed();
        }
    }

    /* renamed from: com.dnielectura.NFCOperationsEncKitKat$6 */
    class C00406 implements View.OnClickListener {
        C00406() {
        }

        public void onClick(View v) {
            NFCOperationsEncKitKat.this.startActivityForResult(new Intent(NFCOperationsEncKitKat.this, DataConfiguration.class), 1);
        }
    }

    public class MyTaskDG11 extends AsyncTask<Void, Integer, Void> {
        private boolean bHayErrores = false;

        protected void onPreExecute() {
            NFCOperationsEncKitKat.this.myHandler.post(NFCOperationsEncKitKat.this.newRead);
            NFCOperationsEncKitKat.this.mForzamosReinicio = true;
            NFCOperationsEncKitKat.this.progressBar.setIndeterminate(true);
            NFCOperationsEncKitKat.this.progressBar.setCancelable(false);
            NFCOperationsEncKitKat.this.progressBar.setTitle(C0041R.string.process_title);
            NFCOperationsEncKitKat.this.progressBar.setMessage(NFCOperationsEncKitKat.this.getApplicationContext().getString(C0041R.string.process_msg_dni));
            NFCOperationsEncKitKat.this.textoProcessDlg = NFCOperationsEncKitKat.this.getApplicationContext().getString(C0041R.string.process_msg_dni);
        }

        protected Void doInBackground(Void... params) {
            try {
                NFCOperationsEncKitKat.this.CargarDGs();
                NFCOperationsEncKitKat.this.mForzamosReinicio = false;
            } catch (PaceException e) {
                NFCOperationsEncKitKat.this.textoResultPage = e.getMessage();
                NFCOperationsEncKitKat.this.mForzamosReinicio = false;
                this.bHayErrores = true;
            } catch (Exception e2) {
                NFCOperationsEncKitKat.this.textoResultPage = "Ocurrió un error durante la lectura de los DGs.";
                if (e2.getMessage() != null) {
                    if (e2.getMessage().contains("lost")) {
                        NFCOperationsEncKitKat.this.textoResultPage = "Error de comunicación. Se ha perdido la conexión con el DNIe.";
                    } else {
                        NFCOperationsEncKitKat.this.textoResultPage = e2.getMessage();
                    }
                }
            }
            return null;
        }

        protected void onPostExecute(Void result) {
            NFCOperationsEncKitKat.this.progressBar.dismiss();
            NFCOperationsEncKitKat.this.m_ksUserMrtd = null;
            if (NFCOperationsEncKitKat.this.mForzamosReinicio) {
                NFCOperationsEncKitKat.this.myHandler.post(NFCOperationsEncKitKat.this.askForRead);
                NFCOperationsEncKitKat.this.readerModeON = NFCOperationsEncKitKat.this.EnableReaderMode(250);
            } else if (this.bHayErrores) {
                NFCOperationsEncKitKat.this.HandleError(NFCOperationsEncKitKat.this.textoResultPage);
            } else {
                Bundle b = new Bundle();
                if (NFCOperationsEncKitKat.this.m_dg1 != null) {
                    b.putByteArray("DGP_DG1", NFCOperationsEncKitKat.this.m_dg1.getBytes());
                }
                if (NFCOperationsEncKitKat.this.m_dg2 != null) {
                    b.putByteArray("DGP_DG2", NFCOperationsEncKitKat.this.m_dg2.getBytes());
                }
                if (NFCOperationsEncKitKat.this.m_dg7 != null) {
                    b.putByteArray("DGP_DG7", NFCOperationsEncKitKat.this.m_dg7.getBytes());
                }
                if (NFCOperationsEncKitKat.this.m_dg11 != null) {
                    b.putByteArray("DGP_DG11", NFCOperationsEncKitKat.this.m_dg11.getBytes());
                }
                if (NFCOperationsEncKitKat.this.m_dg13 != null) {
                    b.putByteArray("DGP_DG13", NFCOperationsEncKitKat.this.m_dg13.getBytes());
                }
                Intent myResultIntent = new Intent(NFCOperationsEncKitKat.this, DataResult.class);
                myResultIntent.putExtras(b);
                NFCOperationsEncKitKat.this.startActivityForResult(myResultIntent, 1);
            }
        }
    }

    public void HandleError(String strError) {
        Bundle b = new Bundle();
        b.putString("ERROR_MSG", strError);
        Intent myResultIntent = new Intent(this, DataErrorActivity.class);
        myResultIntent.putExtras(b);
        startActivity(myResultIntent);
    }

    public void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        requestWindowFeature(1);
        setContentView(C0041R.layout.nfcactkitkat);
        this.tagFromIntent = null;
        this.myContext = this;
        this.myActivity = (Activity) this.myContext;
        myNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        myNfcAdapter.setNdefPushMessage(null, this, new Activity[0]);
        myNfcAdapter.setNdefPushMessageCallback(null, this, new Activity[0]);
        this.m_dg1 = null;
        this.m_dg2 = null;
        this.m_dg7 = null;
        this.m_dg11 = null;
        this.m_dg13 = null;
        this.progressBar = new ProgressDialog(this.myContext);
        findViewById(C0041R.id.resultinfo).setVisibility(4);
        this.cansDO = new CANSpecDOStore(this);
        this.canDnie = ((MyAppDNIELECTURA) getApplicationContext()).getCAN();
        this.fontType = Typeface.createFromAsset(this.myContext.getAssets(), "fonts/HelveticaNeue.ttf");
        ((TextView) findViewById(C0041R.id.result1)).setTypeface(this.fontType);
        TextView myText = (TextView) findViewById(C0041R.id.resultinfo);
        myText.setVisibility(4);
        myText.setTypeface(this.fontType);
        ((Button) findViewById(C0041R.id.butVolver)).setOnClickListener(new C00395());
        ((Button) findViewById(C0041R.id.butConfigurar)).setOnClickListener(new C00406());
    }

    public void onResume() {
        super.onResume();
        if (!this.readerModeON) {
            this.readerModeON = EnableReaderMode(1000);
        }
        if (!myNfcAdapter.isEnabled()) {
            this.myHandler.post(this.askForEnablingNFC);
        }
    }

    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode != 4) {
            return super.onKeyDown(keyCode, event);
        }
        startActivity(new Intent(this, DNIeLectura.class));
        return false;
    }

    private boolean EnableReaderMode(int msDelay) {
        Bundle options = new Bundle();
        options.putInt("presence", msDelay);
        myNfcAdapter.enableReaderMode(this.myActivity, this, 131, options);
        return true;
    }

    private boolean DisableReaderMode() {
        myNfcAdapter.disableReaderMode(this);
        this.readerModeON = false;
        return true;
    }

    public void onTagDiscovered(Tag tag) {
        try {
            this.tagFromIntent = tag;
            new MyTaskDG11().execute(new Void[0]);
        } catch (Exception e) {
            this.textoResultPage = "Ocurrió un error durante la lectura de ficheros.\n" + e.getMessage();
        }
    }

    public boolean CargarDGs() throws PaceException, Exception {
        this.textoProcessDlg = "Leyendo datos...";
        this.myHandler.post(this.updateStatus);
        System.setProperty("es.gob.jmulticard.fastmode", PolicyUtils.TRUE);
        DnieProvider p = new DnieProvider();
        p.setProviderTag(this.tagFromIntent);
        String can6digitos = this.canDnie.getCanNumber();
        while (can6digitos.length() < 6) {
            can6digitos = "0" + can6digitos;
        }
        p.setProviderCan(can6digitos);
        Security.insertProviderAt(p, 1);
        this.m_ksUserMrtd = new DnieKeyStore(new MrtdKeyStoreImpl(), p, "MRTD");
        this.m_ksUserMrtd.load(null, null);
        readUserConfiguration();
        try {
            byte[] tagList = this.m_ksUserMrtd.getEFCOM().getTagList();
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
            if (m_readDg1 && this.m_existDg1) {
                this.m_dg1 = this.m_ksUserMrtd.getDatagroup1();
            }
            if (m_readDg11 && this.m_existDg11) {
                this.m_dg11 = this.m_ksUserMrtd.getDatagroup11();
            }
            if (this.canDnie.getUserNif().length() == 0) {
                String docNumber;
                String certSubject = this.m_dg1.getName() + " " + this.m_dg1.getSurname();
                if (this.m_dg11 == null) {
                    docNumber = this.m_dg1.getDocNumber();
                } else {
                    docNumber = this.m_dg11.getPersonalNumber();
                }
                CANSpecDO newCan = new CANSpecDO(this.canDnie.getCanNumber(), certSubject, docNumber);
                this.cansDO.delete(this.canDnie);
                this.cansDO.save(newCan);
            }
            if (m_readDg2 && this.m_existDg2) {
                this.textoProcessDlg = "Cargando foto...";
                this.myHandler.post(this.updateStatus);
                this.m_dg2 = this.m_ksUserMrtd.getDatagroup2();
            }
            if (m_readDg7 && this.m_existDg7) {
                this.textoProcessDlg = "Cargando firma...";
                this.myHandler.post(this.updateStatus);
                this.m_dg7 = this.m_ksUserMrtd.getDatagroup7();
            }
            if (this.m_existDg13 && (m_readDg13 || this.m_dg1.getDocType().compareTo("ID") == 0)) {
                this.m_dg13 = this.m_ksUserMrtd.getDatagroup13();
            }
            return true;
        } catch (Exception e) {
            Toast.makeText(this.myContext, "Error en la lectura del DG-13", 0).show();
            e.printStackTrace();
            throw e;
        } catch (Exception e2) {
            Toast.makeText(this.myContext, "Error en la lectura del DG-7", 0).show();
            e2.printStackTrace();
            throw e2;
        } catch (Exception e22) {
            Toast.makeText(this.myContext, "Error en la lectura del DG-2", 0).show();
            e22.printStackTrace();
            throw e22;
        } catch (Exception e222) {
            Toast.makeText(this.myContext, "Error en la lectura del DG-11", 0).show();
            e222.printStackTrace();
            throw e222;
        } catch (Exception e2222) {
            Toast.makeText(this.myContext, "Error en la lectura del DG-1", 0).show();
            e2222.printStackTrace();
            throw e2222;
        } catch (Exception e22222) {
            e22222.printStackTrace();
            throw e22222;
        } catch (Exception e222222) {
            e222222.printStackTrace();
            this.textoResultPage = "Ocurrió un error durante la lectura de los DGs.\n";
            if (e222222.getMessage() != null) {
                if (e222222.getMessage().contains("CAN incorrecto")) {
                    this.textoResultPage = "Error al montar canal PACE. CAN incorrecto.";
                    throw new PaceException(this.textoResultPage);
                } else if (e222222.getMessage().contains("Tag was lost")) {
                    this.textoResultPage += "Se perdió la conexión inalámbrica con el DNI electrónico.";
                    throw new Exception(this.textoResultPage);
                } else {
                    this.textoResultPage += e222222.getMessage();
                }
            }
            throw new Exception(this.textoResultPage);
        }
    }

    public void readUserConfiguration() {
        SharedPreferences sharedPreferences = getApplicationContext().getSharedPreferences("com.sp.main_preferences", 0);
        m_readDg1 = true;
        m_readDg2 = sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG2, true);
        m_readDg7 = sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG7, false);
        m_readDg11 = sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG11, true);
        m_readDg13 = sharedPreferences.getBoolean(DNIeLectura.SETTING_READ_DG13, true);
    }
}
