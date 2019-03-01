package de.tsenger.androsmex.data;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import java.util.Vector;

public class CANSpecDOStore {
    private static final String COL_DOC_NAME = "USERNAME";
    private static final String COL_DOC_NIF = "USERNIF";
    private static final String COL_DOC_NUM = "CANNUM";
    private static final int DATABASE_VERSION = 1;
    private static final String DB_NAME = "mrtdcanlist.db";
    private static final String TABLE_CAN = "can";
    private DatabaseHelper helper;

    private static class DatabaseHelper extends SQLiteOpenHelper {
        private static DatabaseHelper mInstance = null;

        DatabaseHelper(Context context) {
            super(context, CANSpecDOStore.DB_NAME, null, 1);
        }

        public static DatabaseHelper getInstance(Context ctx) {
            if (mInstance == null) {
                mInstance = new DatabaseHelper(ctx.getApplicationContext());
            }
            return mInstance;
        }

        public void onCreate(SQLiteDatabase db) {
            db.execSQL("CREATE TABLE can (CANNUM STRING PRIMARY KEY,USERNAME STRING,USERNIF STRING);");
        }

        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            db.execSQL("DROP TABLE IF EXISTS can");
            onCreate(db);
        }
    }

    public CANSpecDOStore(Context context) {
        this.helper = DatabaseHelper.getInstance(context);
    }

    private boolean has(String docNumber) {
        Cursor c = this.helper.getWritableDatabase().query(TABLE_CAN, null, "CANNUM='" + docNumber + "'", null, null, null, null);
        int count = c.getCount();
        c.close();
        return count > 0;
    }

    public Vector<CANSpecDO> getAll() {
        Cursor c = this.helper.getWritableDatabase().query(TABLE_CAN, null, null, null, null, null, null);
        Vector<CANSpecDO> result = new Vector();
        if (c.getCount() > 0) {
            c.moveToFirst();
            do {
                result.add(new CANSpecDO(getCanNumber(c), getUserName(c), getUserNif(c)));
            } while (c.moveToNext());
        }
        c.close();
        return result;
    }

    private String getCanNumber(Cursor c) {
        return c.getString(c.getColumnIndex(COL_DOC_NUM));
    }

    private String getUserName(Cursor c) {
        return c.getString(c.getColumnIndex(COL_DOC_NAME));
    }

    private String getUserNif(Cursor c) {
        return c.getString(c.getColumnIndex(COL_DOC_NIF));
    }

    public boolean contains(CANSpecDO b) {
        if (has(b.getCanNumber())) {
            return true;
        }
        return false;
    }

    public void save(CANSpecDO b) {
        if (has(b.getCanNumber())) {
            update(b);
        } else {
            insert(b);
        }
    }

    private void insert(CANSpecDO b) {
        SQLiteDatabase db = this.helper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COL_DOC_NUM, b.getCanNumber());
        values.put(COL_DOC_NAME, b.getUserName());
        values.put(COL_DOC_NIF, b.getUserNif());
        db.insert(TABLE_CAN, null, values);
        db.close();
    }

    private void update(CANSpecDO b) {
        SQLiteDatabase db = this.helper.getWritableDatabase();
        String where = "CANNUM='" + b.getCanNumber() + "'";
        ContentValues values = new ContentValues();
        values.put(COL_DOC_NUM, b.getCanNumber());
        values.put(COL_DOC_NAME, b.getUserName());
        values.put(COL_DOC_NIF, b.getUserNif());
        db.update(TABLE_CAN, values, where, null);
        db.close();
    }

    public void delete(CANSpecDO b) {
        SQLiteDatabase db = this.helper.getWritableDatabase();
        db.delete(TABLE_CAN, "CANNUM='" + b.getCanNumber() + "'", null);
        db.close();
    }
}
