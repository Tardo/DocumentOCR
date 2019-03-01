package com.dnielectura;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.AdapterView.OnItemLongClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;
import de.tsenger.androsmex.data.CANSpecDO;
import de.tsenger.androsmex.data.CANSpecDOStore;
import java.util.ArrayList;
import java.util.Iterator;

public class DNIeCanSelection extends Activity implements OnClickListener, OnItemLongClickListener, OnItemClickListener {
    private static final String[] ACTION_LABELS = new String[]{ACTION_LABEL_READ, ACTION_LABEL_EDIT, ACTION_LABEL_DELETE};
    private static final String ACTION_LABEL_DELETE = "Borrar";
    private static final String ACTION_LABEL_EDIT = "Modificar";
    private static final String ACTION_LABEL_READ = "Leer";
    private static final int REQ_EDIT_CAN = 2;
    private static final int REQ_EDIT_NEW_CAN = 1;
    private static final int REQ_READ_PP = 3;
    AlertDialog ad = null;
    private CANSpecDOStore cans;
    private Typeface fontType;
    private ArrayAdapter<CANSpecDO> listA;
    private ListView listW;
    private SampleAdapter m_adapter;
    ArrayList<MrtdItem> mrtdItems = new ArrayList();
    private Context myContext = null;
    private Button readNewW;
    private CANSpecDO selectedBac;

    /* renamed from: com.dnielectura.DNIeCanSelection$1 */
    class C00001 implements OnClickListener {
        C00001() {
        }

        public void onClick(View v) {
            DNIeCanSelection.this.startActivity(new Intent(DNIeCanSelection.this, DNIeLectura.class));
            DNIeCanSelection.this.finish();
        }
    }

    /* renamed from: com.dnielectura.DNIeCanSelection$2 */
    class C00012 implements OnClickListener {
        C00012() {
        }

        public void onClick(View v) {
            DNIeCanSelection.this.startActivityForResult(new Intent(DNIeCanSelection.this, DataConfiguration.class), 1);
        }
    }

    /* renamed from: com.dnielectura.DNIeCanSelection$3 */
    class C00023 implements DialogInterface.OnClickListener {
        C00023() {
        }

        public void onClick(DialogInterface dialog, int which) {
            EditText text = (EditText) DNIeCanSelection.this.ad.findViewById(C0041R.id.can_editbox);
            if (text.getText().length() != 6) {
                Toast.makeText(DNIeCanSelection.this.myContext, C0041R.string.help_can_len, 1).show();
                return;
            }
            CANSpecDO can = new CANSpecDO(text.getText().toString(), "", "");
            DNIeCanSelection.this.cans.save(can);
            DNIeCanSelection.this.refreshAdapter();
            DNIeCanSelection.this.read(can);
        }
    }

    /* renamed from: com.dnielectura.DNIeCanSelection$4 */
    class C00034 implements DialogInterface.OnClickListener {
        C00034() {
        }

        public void onClick(DialogInterface dialog, int which) {
        }
    }

    /* renamed from: com.dnielectura.DNIeCanSelection$5 */
    class C00045 implements OnClickListener {
        C00045() {
        }

        public void onClick(View view) {
            Toast.makeText(DNIeCanSelection.this.myContext, C0041R.string.help_can, 1).show();
        }
    }

    /* renamed from: com.dnielectura.DNIeCanSelection$7 */
    class C00067 implements DialogInterface.OnClickListener {
        C00067() {
        }

        public void onClick(DialogInterface dialog, int which) {
        }
    }

    /* renamed from: com.dnielectura.DNIeCanSelection$8 */
    class C00078 implements OnClickListener {
        C00078() {
        }

        public void onClick(View view) {
            Toast.makeText(DNIeCanSelection.this.myContext, C0041R.string.help_can, 1).show();
        }
    }

    /* renamed from: com.dnielectura.DNIeCanSelection$9 */
    class C00089 implements DialogInterface.OnClickListener {
        C00089() {
        }

        public void onClick(DialogInterface dialog, int item) {
            switch (item) {
                case 0:
                    DNIeCanSelection.this.read(DNIeCanSelection.this.selectedBac);
                    return;
                case 1:
                    DNIeCanSelection.this.edit(DNIeCanSelection.this.selectedBac);
                    return;
                case 2:
                    DNIeCanSelection.this.delete(DNIeCanSelection.this.selectedBac);
                    return;
                default:
                    return;
            }
        }
    }

    private class MrtdItem {
        public final String strCan;
        public final String strName;
        public final String strNif;

        public MrtdItem(String strCan, String strName, String strNif) {
            this.strCan = strCan;
            this.strName = strName;
            this.strNif = strNif;
        }
    }

    public class SampleAdapter extends ArrayAdapter<MrtdItem> {
        private Context context;
        private ArrayList<MrtdItem> items;
        private LayoutInflater vi;

        /* renamed from: com.dnielectura.DNIeCanSelection$SampleAdapter$1 */
        class C00091 implements OnClickListener {
            C00091() {
            }

            public void onClick(View v) {
                DNIeCanSelection.this.selectedBac = (CANSpecDO) DNIeCanSelection.this.listA.getItem(DNIeCanSelection.this.listW.getPositionForView((RelativeLayout) v.getParent()));
                DNIeCanSelection.this.delete(DNIeCanSelection.this.selectedBac);
            }
        }

        public SampleAdapter(Context context, ArrayList<MrtdItem> items) {
            super(context, 0, items);
            this.context = context;
            this.items = items;
            this.vi = (LayoutInflater) context.getSystemService("layout_inflater");
        }

        public SampleAdapter(Context context) {
            super(context, 0);
        }

        public View getView(int position, View convertView, ViewGroup parent) {
            View v = convertView;
            MrtdItem ei = (MrtdItem) this.items.get(position);
            if (ei != null) {
                v = this.vi.inflate(C0041R.layout.list_mrtd_row, null);
                TextView title = (TextView) v.findViewById(C0041R.id.row_title);
                TextView name = (TextView) v.findViewById(C0041R.id.row_name);
                TextView nif = (TextView) v.findViewById(C0041R.id.row_nif);
                if (title != null) {
                    title.setText(ei.strCan);
                    title.setTypeface(DNIeCanSelection.this.fontType);
                }
                if (name != null) {
                    name.setText(ei.strName);
                    name.setTypeface(DNIeCanSelection.this.fontType);
                }
                if (nif != null) {
                    nif.setText(ei.strNif);
                    nif.setTypeface(DNIeCanSelection.this.fontType);
                }
                ((Button) v.findViewById(C0041R.id.Btn_DESTROYENTRY)).setOnClickListener(new C00091());
            }
            return v;
        }
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.myContext = this;
        requestWindowFeature(1);
        setContentView(C0041R.layout.can_list);
        this.cans = new CANSpecDOStore(this);
        prepareWidgets();
        this.fontType = Typeface.createFromAsset(this.myContext.getAssets(), "fonts/HelveticaNeue.ttf");
        ((TextView) findViewById(C0041R.id.can_TEXT)).setTypeface(this.fontType);
        ((Button) findViewById(C0041R.id.butVolver)).setOnClickListener(new C00001());
        ((Button) findViewById(C0041R.id.butConfigurar)).setOnClickListener(new C00012());
    }

    private void prepareWidgets() {
        this.readNewW = (Button) findViewById(C0041R.id.BtnCAN_NEW);
        this.readNewW.setOnClickListener(this);
        this.listW = (ListView) findViewById(C0041R.id.canList);
        this.listA = new ArrayAdapter(this, 17367043, this.cans.getAll());
        for (int idx = 0; idx < this.listA.getCount(); idx++) {
            CANSpecDO canItem = (CANSpecDO) this.listA.getItem(idx);
            String can6digitos = canItem.getCanNumber();
            while (can6digitos.length() < 6) {
                can6digitos = "0" + can6digitos;
            }
            this.mrtdItems.add(new MrtdItem(can6digitos, canItem.getUserName(), canItem.getUserNif()));
        }
        this.m_adapter = new SampleAdapter(getApplicationContext(), this.mrtdItems);
        this.listW.setAdapter(this.m_adapter);
        this.listW.setOnItemClickListener(this);
        this.listW.setOnItemLongClickListener(this);
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        setIntent(data);
        if (requestCode == 1) {
            if (resultCode == -1) {
                CANSpecDO can = (CANSpecDO) data.getExtras().getParcelable(CANSpecDO.EXTRA_CAN);
                this.cans.save(can);
                refreshAdapter();
                read(can);
            }
        } else if (requestCode == 2) {
            if (resultCode == -1) {
                this.cans.save((CANSpecDO) data.getExtras().getParcelable(CANSpecDO.EXTRA_CAN));
                refreshAdapter();
            }
        } else if (requestCode != 3) {
        } else {
            if (resultCode == -1) {
                Intent i;
                if (VERSION.SDK_INT <= 18) {
                    i = new Intent(this, DNIeReader.class).putExtras(data.getExtras());
                } else {
                    i = new Intent(this, NFCOperationsEncKitKat.class).putExtras(data.getExtras());
                }
                startActivityForResult(i, 1);
            } else if (resultCode == 0) {
                toastIt("error");
            }
        }
    }

    public void onClick(View v) {
        if (v == this.readNewW) {
            View canEntryView = LayoutInflater.from(this.myContext).inflate(C0041R.layout.can_entry, null);
            this.ad = new Builder(this.myContext).create();
            this.ad.setCancelable(false);
            this.ad.setIcon(C0041R.drawable.alert_dialog_icon);
            this.ad.setView(canEntryView);
            this.ad.setButton(-1, getString(C0041R.string.psswd_dialog_ok), new C00023());
            this.ad.setButton(-2, getString(C0041R.string.psswd_dialog_cancel), new C00034());
            ((Button) canEntryView.findViewById(C0041R.id.helpButton)).setOnClickListener(new C00045());
            this.ad.show();
            ((TextView) this.ad.findViewById(C0041R.id.can_textview)).setTypeface(this.fontType);
            ((TextView) this.ad.findViewById(C0041R.id.can_textboxdescription2)).setTypeface(this.fontType);
            ((EditText) this.ad.findViewById(C0041R.id.can_editbox)).setTypeface(this.fontType);
        }
    }

    private void read(CANSpecDO b) {
        ArrayList cans = new ArrayList();
        cans.add(b);
        ((MyAppDNIELECTURA) getApplicationContext()).setCAN(b);
        read(cans);
    }

    private void read(ArrayList<CANSpecDO> bs) {
        Intent i;
        if (VERSION.SDK_INT <= 18) {
            i = new Intent(this, DNIeReader.class).putParcelableArrayListExtra(CANSpecDO.EXTRA_CAN_COL, bs).setAction(DNIeReader.ACTION_READ);
        } else {
            i = new Intent(this, NFCOperationsEncKitKat.class);
        }
        startActivityForResult(i, 1);
    }

    private void delete(CANSpecDO b) {
        this.cans.delete(b);
        refreshAdapter();
    }

    private void edit(final CANSpecDO b) {
        View canEntryView = LayoutInflater.from(this.myContext).inflate(C0041R.layout.can_entry, null);
        this.ad = new Builder(this.myContext).create();
        this.ad.setCancelable(false);
        this.ad.setIcon(C0041R.drawable.alert_dialog_icon);
        this.ad.setView(canEntryView);
        this.ad.setTitle(getString(C0041R.string.title_dlg_newcan));
        this.ad.setButton(-1, getString(C0041R.string.psswd_dialog_ok), new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                EditText text = (EditText) DNIeCanSelection.this.ad.findViewById(C0041R.id.can_editbox);
                if (text.getText().length() != 6) {
                    Toast.makeText(DNIeCanSelection.this.myContext, C0041R.string.help_can_len, 0).show();
                    return;
                }
                CANSpecDO can = new CANSpecDO(text.getText().toString(), "", "");
                DNIeCanSelection.this.cans.delete(b);
                DNIeCanSelection.this.cans.save(can);
                DNIeCanSelection.this.refreshAdapter();
            }
        });
        this.ad.setButton(-2, getString(C0041R.string.psswd_dialog_cancel), new C00067());
        ((Button) canEntryView.findViewById(C0041R.id.helpButton)).setOnClickListener(new C00078());
        this.ad.show();
        ((TextView) this.ad.findViewById(C0041R.id.can_textview)).setTypeface(this.fontType);
        ((TextView) this.ad.findViewById(C0041R.id.can_textboxdescription2)).setTypeface(this.fontType);
        ((EditText) this.ad.findViewById(C0041R.id.can_editbox)).setTypeface(this.fontType);
        ((EditText) this.ad.findViewById(C0041R.id.can_editbox)).setText(b.getCanNumber());
    }

    private void toastIt(String msg) {
        Toast.makeText(this, msg, 0).show();
    }

    public boolean onItemLongClick(AdapterView<?> adapterView, View view, int position, long id) {
        this.selectedBac = (CANSpecDO) this.listA.getItem(position);
        Builder builder = new Builder(this);
        builder.setTitle("Opciones");
        builder.setItems(ACTION_LABELS, new C00089());
        builder.create().show();
        return true;
    }

    public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
        this.selectedBac = (CANSpecDO) this.listA.getItem(position);
        read(this.selectedBac);
    }

    private void refreshAdapter() {
        this.m_adapter.clear();
        this.listA.clear();
        Iterator it = this.cans.getAll().iterator();
        while (it.hasNext()) {
            this.listA.add((CANSpecDO) it.next());
        }
        for (int idx = 0; idx < this.listA.getCount(); idx++) {
            CANSpecDO canItem = (CANSpecDO) this.listA.getItem(idx);
            this.mrtdItems.add(new MrtdItem(canItem.getCanNumber(), canItem.getUserName(), canItem.getUserNif()));
        }
    }
}
