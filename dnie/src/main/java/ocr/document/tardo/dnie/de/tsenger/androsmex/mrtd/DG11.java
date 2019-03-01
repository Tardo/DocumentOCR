package de.tsenger.androsmex.mrtd;

import custom.org.apache.harmony.xnet.provider.jsse.Handshake;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;

public class DG11 {
    public static final int ADDR_DIRECCION = 1;
    public static final int ADDR_LOCALIDAD = 2;
    public static final int ADDR_PROVINCIA = 3;
    private static final short DOCUMENT_HOLDER_BIRTH_DATE = (short) 24363;
    private static final short DOCUMENT_HOLDER_BIRTH_PLACE = (short) 24337;
    private static final short DOCUMENT_HOLDER_CUSTODY_INFO = (short) 24344;
    private static final short DOCUMENT_HOLDER_FULL_NAME = (short) 24334;
    private static final short DOCUMENT_HOLDER_NAME_ICAO9303 = (short) 24335;
    private static final short DOCUMENT_HOLDER_OTHER_TD = (short) 24343;
    private static final short DOCUMENT_HOLDER_PERMANENT_ADDRESS = (short) 24386;
    private static final short DOCUMENT_HOLDER_PERSONAL_NUMBER = (short) 24336;
    private static final short DOCUMENT_HOLDER_PERSONAL_SUMMARY = (short) 24341;
    private static final short DOCUMENT_HOLDER_PROFESSION = (short) 24339;
    private static final short DOCUMENT_HOLDER_TELEPHONE = (short) 24338;
    private static final short DOCUMENT_HOLDER_TITLE = (short) 24340;
    private static final byte DOCUMENT_TAG_LIST = (byte) 92;
    private HashMap<String, String> countryNames = new HashMap();
    private Date date = null;
    private byte[] holderAddress;
    private byte[] holderBirthDate;
    private byte[] holderBirthPlace;
    private byte[] holderCustodyInfo;
    private byte[] holderIcaoName;
    private byte[] holderName;
    private byte[] holderOther;
    private byte[] holderPersonalNumber;
    private byte[] holderPhone;
    private byte[] holderProfession;
    private byte[] holderSummary;
    private byte[] holderTitle;
    private byte[] parsedData;
    private byte[] rawData;
    private SimpleDateFormat sdFormat = new SimpleDateFormat("yyMMdd");
    private SimpleDateFormat sdFullFormat = new SimpleDateFormat("yyyyMMdd");
    private byte[] tlvAppTemplate = null;

    private void fillHashMap() {
        this.countryNames.put("ABW", "Aruba");
        this.countryNames.put("AFG", "Afghanistan");
        this.countryNames.put("AGO", "Angola");
        this.countryNames.put("AIA", "Anguilla");
        this.countryNames.put("ALA", "Åland Islands");
        this.countryNames.put("ALB", "Albania");
        this.countryNames.put("AND", "Andorra");
        this.countryNames.put("ANT", "Netherlands Antilles");
        this.countryNames.put("ARE", "United Arab Emirates");
        this.countryNames.put("ARG", "Argentina");
        this.countryNames.put("ARM", "Armenia");
        this.countryNames.put("ASM", "American Samoa");
        this.countryNames.put("ATA", "Antarctica");
        this.countryNames.put("ATF", "French Southern Territories");
        this.countryNames.put("ATG", "Antigua and Barbuda");
        this.countryNames.put("AUS", "Australia");
        this.countryNames.put("AUT", "Austria");
        this.countryNames.put("AZE", "Azerbaijan");
        this.countryNames.put("BDI", "Burundi");
        this.countryNames.put("BDR", "Bundesdruckerei");
        this.countryNames.put("BEL", "Belgium");
        this.countryNames.put("BEN", "Benin");
        this.countryNames.put("BFA", "Burkina Faso");
        this.countryNames.put("BGD", "Bangladesh");
        this.countryNames.put("BGR", "Bulgaria");
        this.countryNames.put("BHR", "Bahrain");
        this.countryNames.put("BHS", "Bahamas");
        this.countryNames.put("BIH", "Bosnia and Herzegovina");
        this.countryNames.put("BLR", "Belarus");
        this.countryNames.put("BLZ", "Belize");
        this.countryNames.put("BMU", "Bermuda");
        this.countryNames.put("BOL", "Bolivia");
        this.countryNames.put("BRA", "Brazil");
        this.countryNames.put("BRB", "Barbados");
        this.countryNames.put("BRN", "Brunei Darussalam");
        this.countryNames.put("BTN", "Bhutan");
        this.countryNames.put("BVT", "Bouvet Island");
        this.countryNames.put("BWA", "Botswana");
        this.countryNames.put("CAF", "Central African Republic");
        this.countryNames.put("CAN", "Canada");
        this.countryNames.put("CCK", "Cocos (Keeling) Islands");
        this.countryNames.put("CHE", "Switzerland");
        this.countryNames.put("CHL", "Chile");
        this.countryNames.put("CHN", "China");
        this.countryNames.put("CIV", "Côte d'Ivoire");
        this.countryNames.put("CMR", "Cameroon");
        this.countryNames.put("COD", "Congo, the Democratic Republic of the");
        this.countryNames.put("COG", "Congo");
        this.countryNames.put("COK", "Cook Islands");
        this.countryNames.put("COL", "Colombia");
        this.countryNames.put("COM", "Comoros");
        this.countryNames.put("CPV", "Cape Verde");
        this.countryNames.put("CRI", "Costa Rica");
        this.countryNames.put("CUB", "Cuba");
        this.countryNames.put("CXR", "Christmas Island");
        this.countryNames.put("CYM", "Cayman Islands");
        this.countryNames.put("CYP", "Cyprus");
        this.countryNames.put("CZE", "Czech Republic");
        this.countryNames.put("D", "Germany");
        this.countryNames.put("DJI", "Djibouti");
        this.countryNames.put("DMA", "Dominica");
        this.countryNames.put("DNK", "Denmark");
        this.countryNames.put("DOM", "Dominican Republic");
        this.countryNames.put("DZA", "Algeria");
        this.countryNames.put("ECU", "Ecuador");
        this.countryNames.put("EGY", "Egypt");
        this.countryNames.put("ERI", "Eritrea");
        this.countryNames.put("ESH", "Western Sahara");
        this.countryNames.put("ESP", "Spain");
        this.countryNames.put("EST", "Estonia");
        this.countryNames.put("ETH", "Ethiopia");
        this.countryNames.put("FIN", "Finland");
        this.countryNames.put("FJI", "Fiji");
        this.countryNames.put("FLK", "Falkland Islands (Malvinas)");
        this.countryNames.put("FRA", "France");
        this.countryNames.put("FRO", "Faroe Islands");
        this.countryNames.put("FSM", "Micronesia, Federated States of");
        this.countryNames.put("GAB", "Gabon");
        this.countryNames.put("GBR", "United Kingdom");
        this.countryNames.put("GEO", "Georgia");
        this.countryNames.put("GGY", "Guernsey");
        this.countryNames.put("GHA", "Ghana");
        this.countryNames.put("GIB", "Gibraltar");
        this.countryNames.put("GIN", "Guinea");
        this.countryNames.put("GLP", "Guadeloupe");
        this.countryNames.put("GMB", "Gambia");
        this.countryNames.put("GNB", "Guinea-Bissau");
        this.countryNames.put("GNQ", "Equatorial Guinea");
        this.countryNames.put("GRC", "Greece");
        this.countryNames.put("GRD", "Grenada");
        this.countryNames.put("GRL", "Greenland");
        this.countryNames.put("GTM", "Guatemala");
        this.countryNames.put("GUF", "French Guiana");
        this.countryNames.put("GUM", "Guam");
        this.countryNames.put("GUY", "Guyana");
        this.countryNames.put("HKG", "Hong Kong");
        this.countryNames.put("HMD", "Heard Island and McDonald Islands");
        this.countryNames.put("HND", "Honduras");
        this.countryNames.put("HRV", "Croatia");
        this.countryNames.put("HTI", "Haiti");
        this.countryNames.put("HUN", "Hungary");
        this.countryNames.put("IDN", "Indonesia");
        this.countryNames.put("IMN", "Isle of Man");
        this.countryNames.put("IND", "India");
        this.countryNames.put("IOT", "British Indian Ocean Territory");
        this.countryNames.put("IRL", "Ireland");
        this.countryNames.put("IRN", "Iran, Islamic Republic of");
        this.countryNames.put("IRQ", "Iraq");
        this.countryNames.put("ISL", "Iceland");
        this.countryNames.put("ISR", "Israel");
        this.countryNames.put("ITA", "Italy");
        this.countryNames.put("JAM", "Jamaica");
        this.countryNames.put("JEY", "Jersey");
        this.countryNames.put("JOR", "Jordan");
        this.countryNames.put("JPN", "Japan");
        this.countryNames.put("KAZ", "Kazakhstan");
        this.countryNames.put("KEN", "Kenya");
        this.countryNames.put("KGZ", "Kyrgyzstan");
        this.countryNames.put("KHM", "Cambodia");
        this.countryNames.put("KIR", "Kiribati");
        this.countryNames.put("KNA", "Saint Kitts and Nevis");
        this.countryNames.put("KOR", "Korea, Republic of");
        this.countryNames.put("KWT", "Kuwait");
        this.countryNames.put("LAO", "Lao People's Democratic Republic");
        this.countryNames.put("LBN", "Lebanon");
        this.countryNames.put("LBR", "Liberia");
        this.countryNames.put("LBY", "Libyan Arab Jamahiriya");
        this.countryNames.put("LCA", "Saint Lucia");
        this.countryNames.put("LIE", "Liechtenstein");
        this.countryNames.put("LKA", "Sri Lanka");
        this.countryNames.put("LSO", "Lesotho");
        this.countryNames.put("LTU", "Lithuania");
        this.countryNames.put("LUX", "Luxembourg");
        this.countryNames.put("LVA", "Latvia");
        this.countryNames.put("MAC", "Macao");
        this.countryNames.put("MAR", "Morocco");
        this.countryNames.put("MCO", "Monaco");
        this.countryNames.put("MDA", "Moldova, Republic of");
        this.countryNames.put("MDG", "Madagascar");
        this.countryNames.put("MDV", "Maldives");
        this.countryNames.put("MEX", "Mexico");
        this.countryNames.put("MHL", "Marshall Islands");
        this.countryNames.put("MKD", "Macedonia, the former Yugoslav Republic of");
        this.countryNames.put("MLI", "Mali");
        this.countryNames.put("MLT", "Malta");
        this.countryNames.put("MMR", "Myanmar");
        this.countryNames.put("MNE", "Montenegro");
        this.countryNames.put("MNG", "Mongolia");
        this.countryNames.put("MNP", "Northern Mariana Islands");
        this.countryNames.put("MOZ", "Mozambique");
        this.countryNames.put("MRT", "Mauritania");
        this.countryNames.put("MSR", "Montserrat");
        this.countryNames.put("MTQ", "Martinique");
        this.countryNames.put("MUS", "Mauritius");
        this.countryNames.put("MWI", "Malawi");
        this.countryNames.put("MYS", "Malaysia");
        this.countryNames.put("MYT", "Mayotte");
        this.countryNames.put("NAM", "Namibia");
        this.countryNames.put("NCL", "New Caledonia");
        this.countryNames.put("NER", "Niger");
        this.countryNames.put("NFK", "Norfolk Island");
        this.countryNames.put("NGA", "Nigeria");
        this.countryNames.put("NIC", "Nicaragua");
        this.countryNames.put("NIU", "Niue");
        this.countryNames.put("NLD", "Netherlands");
        this.countryNames.put("NOR", "Norway");
        this.countryNames.put("NPL", "Nepal");
        this.countryNames.put("NRU", "Nauru");
        this.countryNames.put("NZL", "New Zealand");
        this.countryNames.put("OMN", "Oman");
        this.countryNames.put("PAK", "Pakistan");
        this.countryNames.put("PAN", "Panama");
        this.countryNames.put("PCN", "Pitcairn");
        this.countryNames.put("PER", "Peru");
        this.countryNames.put("PHL", "Philippines");
        this.countryNames.put("PLW", "Palau");
        this.countryNames.put("PNG", "Papua New Guinea");
        this.countryNames.put("POL", "Poland");
        this.countryNames.put("PRI", "Puerto Rico");
        this.countryNames.put("PRK", "Korea, Democratic People's Republic of");
        this.countryNames.put("PRT", "Portugal");
        this.countryNames.put("PRY", "Paraguay");
        this.countryNames.put("PSE", "Palestinian Territory, Occupied");
        this.countryNames.put("PYF", "French Polynesia");
        this.countryNames.put("QAT", "Qatar");
        this.countryNames.put("REU", "Réunion");
        this.countryNames.put("ROU", "Romania");
        this.countryNames.put("RUS", "Russian Federation");
        this.countryNames.put("RWA", "Rwanda");
        this.countryNames.put("SAU", "Saudi Arabia");
        this.countryNames.put("SDN", "Sudan");
        this.countryNames.put("SEN", "Senegal");
        this.countryNames.put("SGP", "Singapore");
        this.countryNames.put("SGS", "South Georgia and the South Sandwich Islands");
        this.countryNames.put("SHN", "Saint Helena");
        this.countryNames.put("SJM", "Svalbard and Jan Mayen");
        this.countryNames.put("SLB", "Solomon Islands");
        this.countryNames.put("SLE", "Sierra Leone");
        this.countryNames.put("SLV", "El Salvador");
        this.countryNames.put("SMR", "San Marino");
        this.countryNames.put("SOM", "Somalia");
        this.countryNames.put("SPM", "Saint Pierre and Miquelon");
        this.countryNames.put("SRB", "Serbia");
        this.countryNames.put("STP", "Sao Tome and Principe");
        this.countryNames.put("SUR", "Suriname");
        this.countryNames.put("SVK", "Slovakia");
        this.countryNames.put("SVN", "Slovenia");
        this.countryNames.put("SWE", "Sweden");
        this.countryNames.put("SWZ", "Swaziland");
        this.countryNames.put("SYC", "Seychelles");
        this.countryNames.put("SYR", "Syrian Arab Republic");
        this.countryNames.put("TCA", "Turks and Caicos Islands");
        this.countryNames.put("TCD", "Chad");
        this.countryNames.put("TGO", "Togo");
        this.countryNames.put("THA", "Thailand");
        this.countryNames.put("TJK", "Tajikistan");
        this.countryNames.put("TKL", "Tokelau");
        this.countryNames.put("TKM", "Turkmenistan");
        this.countryNames.put("TLS", "Timor-Leste");
        this.countryNames.put("TON", "Tonga");
        this.countryNames.put("TTO", "Trinidad and Tobago");
        this.countryNames.put("TUN", "Tunisia");
        this.countryNames.put("TUR", "Turkey");
        this.countryNames.put("TUV", "Tuvalu");
        this.countryNames.put("TWN", "Taiwan, Province of China");
        this.countryNames.put("TZA", "Tanzania, United Republic of");
        this.countryNames.put("UGA", "Uganda");
        this.countryNames.put("UKR", "Ukraine");
        this.countryNames.put("UMI", "United States Minor Outlying Islands");
        this.countryNames.put("URY", "Uruguay");
        this.countryNames.put("USA", "United States");
        this.countryNames.put("UTO", "Utopia");
        this.countryNames.put("UZB", "Uzbekistan");
        this.countryNames.put("VAT", "Holy See (Vatican City State)");
        this.countryNames.put("VCT", "Saint Vincent and the Grenadines");
        this.countryNames.put("VEN", "Venezuela");
        this.countryNames.put("VGB", "Virgin Islands, British");
        this.countryNames.put("VIR", "Virgin Islands, U.S.");
        this.countryNames.put("VNM", "Viet Nam");
        this.countryNames.put("VUT", "Vanuatu");
        this.countryNames.put("WLF", "Wallis and Futuna");
        this.countryNames.put("WSM", "Samoa");
        this.countryNames.put("YEM", "Yemen");
        this.countryNames.put("ZAF", "South Africa");
        this.countryNames.put("ZMB", "Zambia");
        this.countryNames.put("ZWE", "Zimbabwe");
    }

    public DG11(byte[] rawBytes) {
        this.rawData = (byte[]) rawBytes.clone();
        this.tlvAppTemplate = ASN1Tools.extractTag(DOCUMENT_TAG_LIST, rawBytes, 0);
        this.parsedData = Arrays.copyOfRange((byte[]) rawBytes.clone(), this.tlvAppTemplate.length + 2, rawBytes.length);
        this.holderName = ASN1Tools.extractTLV(DOCUMENT_HOLDER_FULL_NAME, this.parsedData, 0);
        this.holderIcaoName = ASN1Tools.extractTLV(DOCUMENT_HOLDER_NAME_ICAO9303, this.parsedData, 0);
        this.holderPersonalNumber = ASN1Tools.extractTLV(DOCUMENT_HOLDER_PERSONAL_NUMBER, this.parsedData, 0);
        this.holderBirthDate = ASN1Tools.extractTLV(DOCUMENT_HOLDER_BIRTH_DATE, this.parsedData, 0);
        this.holderBirthPlace = ASN1Tools.extractTLV(DOCUMENT_HOLDER_BIRTH_PLACE, this.parsedData, 0);
        this.holderAddress = ASN1Tools.extractTLV(DOCUMENT_HOLDER_PERMANENT_ADDRESS, this.parsedData, 0);
        this.holderPhone = ASN1Tools.extractTLV(DOCUMENT_HOLDER_TELEPHONE, this.parsedData, 0);
        this.holderProfession = ASN1Tools.extractTLV(DOCUMENT_HOLDER_PROFESSION, this.parsedData, 0);
        this.holderTitle = ASN1Tools.extractTLV(DOCUMENT_HOLDER_TITLE, this.parsedData, 0);
        this.holderSummary = ASN1Tools.extractTLV(DOCUMENT_HOLDER_PERSONAL_SUMMARY, this.parsedData, 0);
        this.holderOther = ASN1Tools.extractTLV(DOCUMENT_HOLDER_OTHER_TD, this.parsedData, 0);
        this.holderCustodyInfo = ASN1Tools.extractTLV(DOCUMENT_HOLDER_CUSTODY_INFO, this.parsedData, 0);
    }

    public String getName() {
        if (this.holderName != null) {
            return new String(ASN1Tools.extractTag(Handshake.SERVER_HELLO_DONE, this.holderName, 1)).substring(2);
        }
        return "";
    }

    public String getIcaoName() {
        if (this.holderIcaoName != null) {
            return new String(ASN1Tools.extractTag(Handshake.CERTIFICATE_VERIFY, this.holderIcaoName, 1)).substring(2);
        }
        return "";
    }

    public String getPersonalNumber() {
        if (this.holderPersonalNumber != null) {
            return new String(ASN1Tools.extractTag((byte) 16, this.holderPersonalNumber, 1)).substring(2);
        }
        return "";
    }

    public String getBirthDate() {
        if (this.holderBirthDate != null) {
            return new String(ASN1Tools.extractTag((byte) 43, this.holderBirthDate, 1)).substring(2);
        }
        return "";
    }

    public String getBirthPlace() {
        if (this.holderBirthPlace != null) {
            return new String(ASN1Tools.extractTag((byte) 17, this.holderBirthPlace, 1)).substring(2);
        }
        return "";
    }

    public String getAddress(int type) {
        if (this.holderAddress == null) {
            return null;
        }
        String address = new String(ASN1Tools.extractTag((byte) 66, this.holderAddress, 1)).substring(2);
        String[] address_components = address.split("<");
        switch (type) {
            case 1:
                return address_components[0];
            case 2:
                return address_components[1];
            case 3:
                return address_components[2];
            default:
                return address;
        }
    }

    public String getPhone() {
        if (this.holderPhone != null) {
            return new String(ASN1Tools.extractTag((byte) 18, this.holderPhone, 1)).substring(2);
        }
        return "";
    }

    public String getProfession() {
        if (this.holderProfession != null) {
            return new String(ASN1Tools.extractTag((byte) 19, this.holderProfession, 1)).substring(2);
        }
        return "";
    }

    public String getTitle() {
        if (this.holderTitle != null) {
            return new String(ASN1Tools.extractTag(Handshake.FINISHED, this.holderTitle, 1)).substring(2);
        }
        return "";
    }

    public String getSummary() {
        if (this.holderSummary != null) {
            return new String(ASN1Tools.extractTag((byte) 21, this.holderSummary, 1)).substring(2);
        }
        return "";
    }

    public String getOtherInfo() {
        if (this.holderOther != null) {
            return new String(ASN1Tools.extractTag((byte) 23, this.holderOther, 1)).substring(2);
        }
        return "";
    }

    public String getCustodyInfo() {
        if (this.holderCustodyInfo != null) {
            return new String(ASN1Tools.extractTag((byte) 24, this.holderCustodyInfo, 1)).substring(2);
        }
        return "";
    }

    public byte[] getBytes() {
        return this.rawData;
    }

    public String getDateOfBirth() {
        if (this.holderBirthDate == null) {
            return "";
        }
        try {
            this.date = this.sdFullFormat.parse(new String(ASN1Tools.extractTag((byte) 95, this.holderBirthDate, 0)));
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return DateFormat.getDateInstance(2).format(this.date);
    }
}
