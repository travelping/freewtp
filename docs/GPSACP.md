# GPSACP message

GPSACP messages are defined in [WTP - SCG Reference Points](https://www.hochbahn.de/hochbahn/wcm/connect/de/1d8945fd-174c-447a-85a5-4a8424406b5a/Lieferung%2Bvon%2BWLAN%2BRoutern%2BAB%2B17.12.2016.pdf?MOD=AJPERES&CACHEID=ROOTWORKSPACE.Z18_JH8I1JC0L05M10AEB6TSP430A1-1d8945fd-174c-447a-85a5-4a8424406b5a-lLovXv0) can be sent within WTP Event Requests.

## Definition GPS Last Acquired Position
The GPS Last Acquired Position contains the output of the AT$GPSACP command from an WWAN Modem.

### Format

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Timestamp                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    WWAN Id    |       GPSATC ....
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Vendor Id** 18681 (Travelping GmbH)

**Type** 15

**Length** >= 5

**Timestamp** The WTP’s time when the meassurment was recorded

**WWAN Id** WWAN Interface Id, used to differentiate between multiple WWAN interfaces, MUST be between
one (1) and 16.

**GPSATC** The full output (including the starting $GPSATC) of the AT$GPSATC command the WWAN Interface:

```
$GPSACP:<UTC>,<latitude>,<longitude>,<hdop>,<altitude>,<fix>,<cog>,<spkm>,<spkn>,<date>,<nsat> 

<UTC>: HHMMSS
  HH: Stunde (00..23)
  MM: Minute (00..59)
  SS: Sekunde (00..60) (Ja - 60 - Schaltsekunden...)
<latitude>: ddmm.mmmmD
  dd: Grad (00..90)
  mm.mmmm: Minuten mit dezimalen Nachkommerstellen (00.0000 .. 59.9999)
  D: Richtung ab Äquator (N|S)
<longitude>: dddmm.mmmmD
  dd: Grad (00..180)
  mm.mmmm: Minuten mit dezimalen Nachkommerstellen (00.0000 .. 59.9999)
  D: Richtung ab Geenwich (W|E)
<hdop>: xx.x
  xx.x: Horizontale genauigkeit in m (00.0..99.9)
<altitude>: xxxx.x
  xxxx.x: Höhe üNN in m (0000.0..9999.9) (Himalaya: Ceck, Holland: Im zweifel leer, wenn unter NN)
<fix>: x
  x: Fix-Status (0: Kein Fix, 1: 2D, 2: 3D)
<cog>: xxx.x
  xxx.x: Course over ground (000.0 .. 359.9)
<spkm>: xxx.x
  xxx.x: Geschwindigkeit in km/h (000.0 .. 999.9)
<spkn>: xxx.x
  xxx.x: Geschwindigkein in Knoten (000.0 .. 999.9)
<date>: ddmmyy
  dd: Tag (01 .. 31)
  mm: Monat (01 .. 12)
  yy: Jahr (00 .. 99)
<nsat>: xx
  xx: Anzahl der sichtbaren Satelliten (00 .. 99)
```
