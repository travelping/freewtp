FreeWTP
=======

Open Source CAPWAP WTP implementation

Version 1.4.1 - 15 Nov 2016
---------------------------

* fix endianness buf in RSNE processing
* command line fixes/enhances
* updated kernel patches for plain upstream and OpenWRT/LEDE
* remove some left over references to SmartCAPWAP
* fix STA removal (make sure the DeAuthentication frame is sent)

Version 1.4.0 - 22 Aug 2016
---------------------------

* renamed to FreeWTP
* RFC-7494 support
* fix DTLS handshake failure handling

Version 1.3.2 - 15 Aug 2016
---------------------------

* support management frame protection

Version 1.3.1 - 11 Aug 2016
---------------------------

* fix hw queue selection for 802.11 raw frame injection
* initial Linux ftrace support

Version 1.3.0 - 08 Aug 2016
---------------------------

* forward PAE (IEEE 802.1X Authentication) frames as raw 802.11 frames to AC
* implement encryption support for group and peer temporal keys (CCMP only)

Version 1.2.1 - 06 May 2016
---------------------------

* fix Add WLAN's capability field
* fix mssing IEEE 802.11 Assigned WTP BSSID IE in Add WLAN response

Version 1.2.0 - 29 Apr 2016
---------------------------

* 802.11n support
* WMM/WME support
* ported to libev
* ported to Linux 4.4
