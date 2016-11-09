# README

[RFC-5415](https://tools.ietf.org/html/rfc5415) and [RFC-5416](https://tools.ietf.org/html/rfc5416) compliant CAPWAP WTP implementation.

This project started as a fork of SmartCAPWAP, but has since dropped the AC part on focuses on WTP functionality only (hence the new name).

## STATUS

### WTP tested and working features:

* 802.11b
* 802.11g
* 802.11a
* WMM/WME (mostly)
* Local MAC
* single radio, single WLAN mode
* 802.11n ([draft-ietf-opsawg-capwap-extension-06](https://tools.ietf.org/html/draft-ietf-opsawg-capwap-extension-06))
* WPA2-PSK
* WPA2 Enterprise

Only cards with cfg80211 netlink API are supported. The following devices
have been tested:

* Atheros AR9280 (Compex WLE200NX)
* Mediatek MT7602E, MT7612E (ZBT WG2626, ALL-WR1200AC_WRT)

### Planned WTP features:

* 802.11r - BSS fast transition
* Hybrid-MAC ([RFC-7494](https://tools.ietf.org/html/rfc7494))

## INSTALLATION

### Requirements

NOTE: To run WTP you must have a wireless card that has Linux driver based on the
      Generic IEEE 802.11 Networking Stack (mac80211).

* Linux 4.4 or newer
* automake 1.9 or newer
* autoconf
* libconfig-dev
* libnl-dev
* libev-dev
* libtool
* wolfssl 3.8 or newer

### Build

Linux Kernel:

Apply the appropriate path from kernel-patches to your kernel, enable
CAPWAP WTP support and rebuild you kernel.

WolfSSL:

    ./configure --enable-dtls --enable-ipv6 --enable-aesgcm \
                --enable-aesccm --enable-aesni --enable-poly1305 \
                --enable-ecc --enable-ecc25519 --enable-chacha \
                --enable-supportedcurves --enable-dh --enable-psk \
                --disable-des3 --disable-arc4 --prefix=/usr/
    make
    make install

FreeWTP:

    autoreconf -f -i
    ./configure --disable-ac
    make
    make install

### Debugging / Tracing

The wtp capwap kernel module defines a number of static ftrace events. For a detailed
guide on how to use those, see: https://www.kernel.org/doc/Documentation/trace/ftrace.txt

A sample trace session might lock like this:

   # echo 1 > /sys/kernel/debug/tracing/events/capwap/enable
   # echo 1 > /sys/kernel/debug/tracing/tracing_on
   # cat /sys/kernel/debug/tracing/trace_pipe
              <...>-890   [000] ...1 12030.725012: sc_capwap_create:  session:9e04b10c75b3c6537da18d38da5bc70d
              <...>-890   [000] ...1 12030.725048: sc_capwap_sendkeepalive:  session:9e04b10c75b3c6537da18d38da5bc70d
              <...>-890   [000] ...1 12030.725052: sc_capwap_createkeepalive:  session:9e04b10c75b3c6537da18d38da5bc70d
              <...>-890   [000] ...1 12030.725053: sc_capwap_send:  session:9e04b10c75b3c6537da18d38da5bc70d
        ksoftirqd/0-3     [000] ..s1 12030.727270: sc_capwap_parsingpacket:  session:9e04b10c75b3c6537da18d38da5bc70d skb:ffff8802306c8900
                wtp-890   [001] ...1 12060.764008: sc_capwap_sendkeepalive:  session:9e04b10c75b3c6537da18d38da5bc70d
                wtp-890   [001] ...1 12060.764530: sc_capwap_createkeepalive:  session:9e04b10c75b3c6537da18d38da5bc70d
                wtp-890   [001] ...1 12060.764637: sc_capwap_send:  session:9e04b10c75b3c6537da18d38da5bc70d
             <idle>-0     [000] ..s2 12060.787527: sc_capwap_parsingpacket:  session:9e04b10c75b3c6537da18d38da5bc70d skb:ffff8800b8a85900
                wtp-890   [001] ...1 12082.953847: sc_capwap_resetsession:  session:9e04b10c75b3c6537da18d38da5bc70d
                wtp-890   [001] ...1 12082.954005: sc_capwap_close:  session:9e04b10c75b3c6537da18d38da5bc70d
                wtp-890   [001] ...1 12082.954130: sc_capwap_freesession:  session:9e04b10c75b3c6537da18d38da5bc70d
   # echo 0 > /sys/kernel/debug/tracing/tracing_on
