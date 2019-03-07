# DocumentOCR -alpha- [![Build Status](https://travis-ci.org/Tardo/DocumentOCR.svg?branch=master)](https://travis-ci.org/Tardo/DocumentOCR)

Android app for create res.partner record reading a DNI or Passport (OCR-B & NFC) with a mobile.

** Supports "hotel_l10n_es" from https://github.com/hootel/hootel/


## ANDROID PROJECT INFO

**App based on https://www.dnielectronico.es/PortalDNIe/PRF1_Cons02.action?pag=REF_036&id_menu=21**

#### Dependencies (included)
  - dniedroid: NFC reader for DNIe card type (Package included in police_es source)
  - tesseract: OCR made easy
  - odoojson-rpc: To communicate with Odoo via JSON-RPC

#### External Resources
  - Tesseract OCR-B trained data by http://trainyourtesseract.com/

#### TO-DO
  - Use new DG's (when released by police_es)


European Regional Development Fund. A way to make Europe.

![ccs] ![ue]

https://www.aldahotels.es/ue/

[ccs]: app/src/main/res/drawable/ccs.png "Camara Comercio Santiago de Compostela"
[ue]: app/src/main/res/drawable/ue.png "Unión Europea"
