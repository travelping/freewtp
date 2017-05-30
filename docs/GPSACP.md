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
|    WWAN Id    |       GPSACP ....
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Vendor Id** 18681 (Travelping GmbH)

**Type** 15

**Length** >= 5

**Timestamp** The WTP’s time when the meassurment was recorded

**WWAN Id** WWAN Interface Id, used to differentiate between multiple WWAN interfaces, MUST be between
one (1) and 16.

**GPSACP** The full output (including the starting $GPSACP) of the AT$GPSACP command the WWAN Interface:

```
$GPSACP:<UTC>,<latitude>,<longitude>,<hdop>,<altitude>,<fix>,<cog>,<spkm>,<spkn>,<date>,<nsat> 

<UTC>: HHMMSS
  HH: Hour of day (00..23)
  MM: Minute (00..59)
  SS: Second (00..60)
<latitude>: ddmm.mmmmD
  dd: Degree (00..90)
  mm.mmmm: Minutes with decimal fraction (00.0000 .. 59.9999)
  D: Direction (N|S)
<longitude>: dddmm.mmmmD
  dd: Degree (00..180)
  mm.mmmm: Minutes with decimal fraction (00.0000 .. 59.9999)
  D: Direction (W|E)
<hdop>: xx.x
  xx.x: Horizontal dilution of precision in m (00.0..99.9)
<altitude>: xxxx.x
  xxxx.x: Altitude above sea level in m (0000.0..9999.9) - Empty value for negative values.
<fix>: x
  x: Fix status (0: No fix, 1: 2D, 2: 3D)
<cog>: xxx.x
  xxx.x: Course over ground (000.0 .. 359.9)
<spkm>: xxx.x
  xxx.x: Horizontal speed in km/h (000.0 .. 999.9)
<spkn>: xxx.x
  xxx.x: Horizontal speed in knots (000.0 .. 999.9)
<date>: ddmmyy
  dd: Day (01 .. 31)
  mm: Month (01 .. 12)
  yy: Year (00 .. 99)
<nsat>: xx
  xx: Number of satallites in view (00 .. 99)
```
