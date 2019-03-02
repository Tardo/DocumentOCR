# DocumentOCR -alpha- ![TravisCI](https://api.travis-ci.org/Tardo/DocumentOCR.svg?branch=master)

Android app for create res.partner record reading a DNI or Passport (OCR-B & NFC) with a mobile.


## ANDROID PROJECT INFO

**App based on https://www.dnielectronico.es/PortalDNIe/PRF1_Cons02.action?pag=REF_036&id_menu=21**

#### Dependencies (included)
  - dniedroid: NFC reader for DNIe card type (Package included in police_es source)
  - tesseract: OCR made easy
  - odoojson-rpc: To communicate with Odoo via JSON-RPC

#### External Resources
  - Tesseract OCR-B trained data by http://trainyourtesseract.com/

#### TO-DO
  - Improve UI/UX
  - Use new DG's (when released by police_es)
  - Complete english translation (Police source is released in hard-coded spanish)
  - Refactor
  - Isolate Odoo Dependencies

## USAGE
#### Odoo Environment Dependencies
  - Need have installed "hotel_l10n_es" from https://github.com/hootel/hootel/
    - _Can be easy modified to use custom fields and avoid module usage._
      - DNIeResultActivity > RPCCreatePartner
      - OCRBResultActivity > RPCCreatePartner
