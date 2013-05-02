#ifndef __IEEE802_11_HEADER__
#define __IEEE802_11_HEADER__

#include <endian.h>
#include <byteswap.h>
#include <inttypes.h>

/* */
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

/* */
typedef u16 be16;
typedef u16 le16;
typedef u32 be32;
typedef u32 le32;
typedef u64 be64;
typedef u64 le64;

/* */
#define STRUCT_PACKED __attribute__ ((packed))

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif
#ifndef ETH_P_80211_ENCAP
#define ETH_P_80211_ENCAP 0x890d 		/* TDLS comes under this category */
#endif
#ifndef ETH_P_PAE
#define ETH_P_PAE 0x888E 				/* Port Access Entity (IEEE 802.1X) */
#endif
#ifndef ETH_P_EAPOL
#define ETH_P_EAPOL ETH_P_PAE
#endif
#ifndef ETH_P_RSN_PREAUTH
#define ETH_P_RSN_PREAUTH 0x88c7
#endif
#ifndef ETH_P_RRB
#define ETH_P_RRB 0x890D
#endif

/* */
#include "ieee802_11_defs.h"
#include "ieee802_11_common.h"

#endif /* __IEEE802_11_HEADER__ */
