#!/bin/sh
#
# The OpenWRT patches are for the mac80211 package. They are functional
# indentical to the kernel patches but need two modifications.
#
# 1. CONFIG_ needs to be replaced with CPTCFG_
# 2. any new configuration option, need to be patched into .local-symbols
#
# This script takes the pure kernel patches and make the above modifications.
#

DIR=$(dirname $0)

rebuild() {
    sed -e"s|CONFIG_|CPTCFG_|g" $DIR/../../kernel-patches/$1 > $DIR/922-$1
    cat >> $DIR/922-$1 <<EOF
--- a/.local-symbols
+++ b/.local-symbols
@@ -42,6 +42,7 @@ LIB80211_CRYPT_CCMP=
 LIB80211_CRYPT_TKIP=
 LIB80211_DEBUG=
 MAC80211=
+MAC80211_CAPWAP_WTP=
 MAC80211_HAS_RC=
 MAC80211_RC_MINSTREL=
 MAC80211_RC_MINSTREL_HT=
EOF
}

for F in $DIR/../../kernel-patches/mac80211_packet_tunnel*patch; do \
    rebuild $(basename $F); \
done
