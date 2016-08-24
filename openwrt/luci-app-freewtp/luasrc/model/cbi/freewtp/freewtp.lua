-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2010-2015 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

m = Map("wtp", translate("FreeWTP"),
  translate("FreeWTP CAPWAP WTP"))

s = m:section(TypedSection, "wtp", nil, translate("Settings"))
s.addremove = false
s.anonymous = true

s:tab("general", translate("General Settings"))
s:tab("ac", translate("Access Controller"))
s:tab("security", translate("Security"))

name = s:taboption("general", Value, "name", translate("Name"),
      translate("Name of the WTP instance."))
name.datatype = "string"

uuid = s:taboption("general", Value, "uuid", translate("ID"),
      translate("Unique Identifier"))
uuid.datatype = "string"
uuid.readonly = true

country = s:taboption("general", Value, "country", translate("Country"),
      translate("ISO/IEC 3166 alpha2 country code"))
country.datatype = "string"

location = s:taboption("general", Value, "location", translate("Location"),
      translate("Geographic location"))
location.datatype = "string"

ac = s:taboption("ac", Value, "host", translate("Access Controller"),
      translate("Hostname of the Access Controller"))
location.datatype = "hostname"

encr = s:taboption("security", ListValue, "dtlsmode", translate("DTLS Security Mode"))
encr:value("off", translate("Disabled"))
encr:value("psk", translate("Pre-shared Key"))
encr:value("x509", translate("X.509"))

ident = s:taboption("security", Value, "identifier", translate("Identifier"),
      translate("Identifier"))
ident:depends("dtlsmode", "psk")
ident.datatype = "string"
ident.rmempty = true

psk = s:taboption("security", Value, "psk", translate("Pre-shared Key"),
      translate("Passphrase"))
psk:depends("dtlsmode", "psk")
psk.datatype = "string"
psk.rmempty = true
psk.password = true

ca = s:taboption("security", FileUpload, "ca", translate("Certification Authority File"))
ca:depends("dtlsmode", "x509")
ca.rmempty = true

cert = s:taboption("security", FileUpload, "cert", translate("Certificate File"))
cert:depends("dtlsmode", "x509")
cert.rmempty = true

key = s:taboption("security", FileUpload, "key", translate("Private Key File"))
key:depends("dtlsmode", "x509")
key.rmempty = true

return m
