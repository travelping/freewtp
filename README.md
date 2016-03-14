# README

[RFC-5415](https://tools.ietf.org/html/rfc5415) and [RFC-5416](https://tools.ietf.org/html/rfc5416) compliant CAPWAP WTP (and AC) implementation.

This fork is currently focusing on the WTP side only.

## STATUS

### WTP tested and working features:

* 802.11b
* 802.11g
* WMM/WME (mostly)
* Local MAC
* single radio, single WLAN mode
* 802.11n ([draft-ietf-opsawg-capwap-extension-06](https://tools.ietf.org/html/draft-ietf-opsawg-capwap-extension-06))

Only cards with cfg80211 netlink API are supported and only
ath9k cards (in particular Qualcomm Atheros AR5418) have
been tested.

### Planned WTP features:

* encryption (WPA2)
* Hybrid-MAC ([RFC-7494](https://tools.ietf.org/html/rfc7494))

## INSTALLATION

### Requirements

NOTE: To run WTP you must have a wireless card that has Linux driver based on the
      Generic IEEE 802.11 Networking Stack (mac80211).

* Linux 4.4 or newer
* automake 1.9 or newer
* autoconf
* libconfig-dev
* libjson0-dev
* libnl-dev
* libtool
* libxml2-dev
* wolfssl 3.8 or newer

### Build

WolfSSL:

    ./configure --enable-dtls --enable-ipv6 --enable-aesgcm \
                --enable-aesccm --enable-aesni --enable-poly1305 \
	            --enable-ecc --enable-ecc25519 --enable-chacha \
				--enable-supportedcurves --enable-dh --enable-psk \
				--disable-des3 --disable-arc4 --prefix=/usr/
    make
    make install

SmartCAPWAP:

    autoreconf -f -i
    ./configure --without-ac
    make
    make install
