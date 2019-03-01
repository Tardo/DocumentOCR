package es.gob.jmulticard.card.iso7816four;

import es.gob.jmulticard.apdu.StatusWord;
import java.util.Hashtable;

public class Iso7816FourCardException extends Exception {
    private static final Hashtable ERRORS = new Hashtable();
    private static final long serialVersionUID = 5935577997660561619L;
    private final StatusWord returnCode;

    static {
        ERRORS.put(new StatusWord((byte) 98, (byte) -125), "El fichero seleccionado esta invalidado");
        ERRORS.put(new StatusWord((byte) 101, (byte) -127), "Fallo en la memoria");
        ERRORS.put(new StatusWord((byte) 103, (byte) 0), "Longitud incorrecta");
        ERRORS.put(new StatusWord((byte) 104, (byte) -126), "Securizacion de mensajes no soportada");
        ERRORS.put(new StatusWord((byte) 105, (byte) -126), "Condiciones de seguridad no satisfechas");
        ERRORS.put(new StatusWord((byte) 105, (byte) -125), "Metodo de autenticacion bloqueado");
        ERRORS.put(new StatusWord((byte) 105, (byte) -124), "Dato referenciado invalido");
        ERRORS.put(new StatusWord((byte) 105, (byte) -123), "Condiciones de uso no satisfechas");
        ERRORS.put(new StatusWord((byte) 105, (byte) -122), "Comando no permitido (no existe ningun EF seleccionado)");
        ERRORS.put(new StatusWord((byte) 106, Byte.MIN_VALUE), "Parametros incorrectos en el campo de datos");
        ERRORS.put(new StatusWord((byte) 106, (byte) -127), "Funcion no soportada.");
        ERRORS.put(new StatusWord((byte) 106, (byte) -126), "No se encuentra el fichero");
        ERRORS.put(new StatusWord((byte) 106, (byte) -125), "Registro no encontrado");
        ERRORS.put(new StatusWord((byte) 106, (byte) -124), "No hay suficiente espacio de memoria en el fichero");
        ERRORS.put(new StatusWord((byte) 106, (byte) -123), "La longitud de datos (Lc) es incompatible con la estructura TLV");
        ERRORS.put(new StatusWord((byte) 106, (byte) -122), "parametros incorrectos en P1 P2");
        ERRORS.put(new StatusWord((byte) 106, (byte) -121), "La longitud de los datos es inconsistente con P1-P2");
        ERRORS.put(new StatusWord((byte) 106, (byte) -120), "Datos referenciados no encontrados");
        ERRORS.put(new StatusWord((byte) 106, (byte) -119), "El fichero ya existe");
        ERRORS.put(new StatusWord((byte) 106, (byte) -118), "El nombre del DF ya existe");
        ERRORS.put(new StatusWord((byte) 107, (byte) 0), "Parametro(s) incorrecto(s) P1-P2");
        ERRORS.put(new StatusWord((byte) 110, (byte) 0), "Clase no soportada");
        ERRORS.put(new StatusWord((byte) 109, (byte) 0), "Comando no permitido en la fase de vida actual");
        ERRORS.put(new StatusWord((byte) 111, (byte) 0), "Diagnostico no preciso");
    }

    Iso7816FourCardException(String desc, StatusWord retCode) {
        super(desc);
        this.returnCode = retCode;
    }

    Iso7816FourCardException(StatusWord retCode) {
        super((String) ERRORS.get(retCode));
        this.returnCode = retCode;
    }

    public StatusWord getStatusWord() {
        return this.returnCode;
    }
}
