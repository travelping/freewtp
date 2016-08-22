#if !defined(__CAPWAP_DRIVER_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define __CAPWAP_DRIVER_TRACE_H

#include <linux/tracepoint.h>
#include <net/mac80211.h>
#include "capwap.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM capwap

#define SESSION_ENTRY		__array(char, sessionid, 16)
#define SESSION_ASSIGN		((session) ? memcpy(__entry->sessionid, &session->sessionid, 16) : memset(__entry->sessionid, 0, 16))
#define SESSION_PR_FMT		" session:%16phN"
#define SESSION_PR_ARG		__entry->sessionid

#define SESSIONID_ENTRY		__array(char, sessionid, 16)
#define SESSIONID_ASSIGN	((sessionid) ? memcpy(__entry->sessionid, sessionid, 16) : memset(__entry->sessionid, 0, 16))
#define SESSIONID_PR_FMT	" session:%16phN"
#define SESSIONID_PR_ARG	__entry->sessionid

#define SKB_ENTRY		__field(struct sk_buff *, skb)
#define SKB_ASSIGN		__entry->skb = skb
#define SKB_PR_FMT		" skb:%p"
#define SKB_PR_ARG		__entry->skb

#define FRAGMENT_ENTRY		__field(struct sc_capwap_fragment *, fragment)
#define FRAGMENT_ASSIGN		__entry->fragment = fragment
#define FRAGMENT_PR_FMT		" frag:%p"
#define FRAGMENT_PR_ARG		__entry->fragment

#define BSSID_ENTRY		__array(char, bssid, ETH_ALEN)
#define BSSID_ASSIGN		(bssid ? memcpy(__entry->bssid, bssid, ETH_ALEN) : memset(__entry->bssid, 0, ETH_ALEN))
#define BSSID_PR_FMT		" BSS:%pM"
#define BSSID_PR_ARG		__entry->bssid

/* capwap.c */

TRACE_EVENT(sc_capwap_fragment_free,
	TP_PROTO(struct sc_capwap_fragment *fragment),

	TP_ARGS(fragment),

	TP_STRUCT__entry(
		FRAGMENT_ENTRY
	),

	TP_fast_assign(
		FRAGMENT_ASSIGN;
	),

	TP_printk(FRAGMENT_PR_FMT, FRAGMENT_PR_ARG)
);

TRACE_EVENT(sc_capwap_freesession,
	TP_PROTO(struct sc_capwap_session *session),

	TP_ARGS(session),

	TP_STRUCT__entry(
		SESSION_ENTRY
	),

	TP_fast_assign(
		SESSION_ASSIGN;
	),

	TP_printk(SESSION_PR_FMT, SESSION_PR_ARG)
);

TRACE_EVENT(sc_capwap_defrag_evictor,
	TP_PROTO(struct sc_capwap_session *session),

	TP_ARGS(session),

	TP_STRUCT__entry(
		SESSION_ENTRY
	),

	TP_fast_assign(
		SESSION_ASSIGN;
	),

	TP_printk(SESSION_PR_FMT, SESSION_PR_ARG)
);

TRACE_EVENT(sc_capwap_defrag_evictor_fragment_expired,
	TP_PROTO(struct sc_capwap_session *session,
		 struct sc_capwap_fragment *fragment,
		 ktime_t now),

	TP_ARGS(session,
		fragment,
		now),

	TP_STRUCT__entry(
		SESSION_ENTRY
		FRAGMENT_ENTRY
		__field(u64, now)
		__field(u64, tstamp)
	),

	TP_fast_assign(
		SESSION_ASSIGN;
		FRAGMENT_ASSIGN;
		__entry->now = now.tv64;
		__entry->tstamp = fragment->tstamp.tv64;
	),

	TP_printk(SESSION_PR_FMT FRAGMENT_PR_FMT " (%llu %llu)",
		  SESSION_PR_ARG, FRAGMENT_PR_ARG,
		  __entry->now,
		  __entry->tstamp
	)
);

TRACE_EVENT(sc_capwap_reasm,
	TP_PROTO(struct sc_capwap_fragment *fragment),

	TP_ARGS(fragment),

	TP_STRUCT__entry(
		FRAGMENT_ENTRY
	),

	TP_fast_assign(
		FRAGMENT_ASSIGN;
	),

	TP_printk(FRAGMENT_PR_FMT, FRAGMENT_PR_ARG)
);

TRACE_EVENT(sc_capwap_defrag,
	TP_PROTO(struct sc_capwap_session *session,
		 uint16_t id,
		 uint16_t offset,
		 uint16_t length),

	TP_ARGS(session, id, offset, length),

	TP_STRUCT__entry(
		SESSION_ENTRY
		__field(u16, id)
		__field(u16, offset)
		__field(u16, length)
	),

	TP_fast_assign(
		SESSION_ASSIGN;
		__entry->id = id;
		__entry->offset = offset;
		__entry->length = length;
	),

	TP_printk(
		SESSION_PR_FMT " fragment id:%hu offset:%hu length:%hu",
		SESSION_PR_ARG, __entry->id, __entry->offset, __entry->length
	)
);


// TRACEKMOD("** *Fragment info: id %hu offset %hu length %hu\n", frag_id, cb->frag_offset, cb->frag_length);

TRACE_EVENT(sc_capwap_8023_to_80211,
	TP_PROTO(struct sk_buff *skb, const uint8_t *bssid),

	TP_ARGS(skb, bssid),

	TP_STRUCT__entry(
		SKB_ENTRY
		BSSID_ENTRY
	),

	TP_fast_assign(
		SKB_ASSIGN;
		BSSID_ASSIGN;
	),

	TP_printk(
		SKB_PR_FMT BSSID_PR_FMT,
		SKB_PR_ARG, BSSID_PR_ARG
	)
);

TRACE_EVENT(sc_capwap_80211_to_8023,
	TP_PROTO(struct sk_buff *skb),

	TP_ARGS(skb),

	TP_STRUCT__entry(
		SKB_ENTRY
	),

	TP_fast_assign(
		SKB_ASSIGN;
	),

	TP_printk(SKB_PR_FMT, SKB_PR_ARG)
);

TRACE_EVENT(sc_capwap_create,
	TP_PROTO(struct sc_capwap_session *session),

	TP_ARGS(session),

	TP_STRUCT__entry(
		SESSION_ENTRY
	),

	TP_fast_assign(
		SESSION_ASSIGN;
	),

	TP_printk(SESSION_PR_FMT, SESSION_PR_ARG)
);

TRACE_EVENT(sc_capwap_close,
	TP_PROTO(struct sc_capwap_session *session),

	TP_ARGS(session),

	TP_STRUCT__entry(
		SESSION_ENTRY
	),

	TP_fast_assign(
		SESSION_ASSIGN;
	),

	TP_printk(SESSION_PR_FMT, SESSION_PR_ARG)
);

TRACE_EVENT(sc_capwap_newfragmentid,
	TP_PROTO(struct sc_capwap_session *session),

	TP_ARGS(session),

	TP_STRUCT__entry(
		SESSION_ENTRY
	),

	TP_fast_assign(
		SESSION_ASSIGN;
	),

	TP_printk(SESSION_PR_FMT, SESSION_PR_ARG)
);

TRACE_EVENT(sc_capwap_createkeepalive,
	TP_PROTO(struct sc_capwap_sessionid_element *sessionid),

	TP_ARGS(sessionid),

	TP_STRUCT__entry(
		SESSIONID_ENTRY
	),

	TP_fast_assign(
		SESSIONID_ASSIGN;
	),

	TP_printk(SESSIONID_PR_FMT, SESSIONID_PR_ARG)
);

TRACE_EVENT(sc_capwap_parsingpacket,
	TP_PROTO(struct sc_capwap_session *session,
		 struct sk_buff *skb),

	TP_ARGS(session, skb),

	TP_STRUCT__entry(
		SESSION_ENTRY
		SKB_ENTRY
	),

	TP_fast_assign(
		SESSION_ASSIGN;
		SKB_ASSIGN;
	),

	TP_printk(
		SESSION_PR_FMT SKB_PR_FMT,
		SESSION_PR_ARG, SKB_PR_ARG
	)
);

TRACE_EVENT(sc_capwap_forwarddata,
	TP_PROTO(struct sc_capwap_session *session,
		 uint8_t radioid,
		 uint8_t binding,
		 struct sk_buff *skb,
		 uint32_t flags,
		 struct sc_capwap_radio_addr *radioaddr,
		 int radioaddrlength,
		 struct sc_capwap_wireless_information *winfo),

	TP_ARGS(session, radioid, binding, skb, flags, radioaddr, radioaddrlength, winfo),

	TP_STRUCT__entry(
		SESSION_ENTRY
		__field(u8, radioid)
		__field(u8, binding)
		SKB_ENTRY
		__field(u32, flags)
		__field(int, radioaddrlength)
		__array(char, radioaddr, 8)
		__field(u8, rssi)
		__field(u8, snr)
		__field(u16, rate)
	),

	TP_fast_assign(
		SESSION_ASSIGN;
		__entry->radioid = radioid;
		__entry->binding = binding;
		SKB_ASSIGN;
		__entry->binding = flags;
		__entry->radioaddrlength = radioaddrlength;
		((radioaddrlength != 0 && radioaddr) ? memcpy(__entry->radioaddr, radioaddr, min(radioaddrlength, 8)) : memset(__entry->radioaddr, 0, 8));

		__entry->rssi = (winfo) ? ((struct sc_capwap_ieee80211_frame_info *)(winfo))->rssi : 0;
		__entry->snr = (winfo) ? ((struct sc_capwap_ieee80211_frame_info *)(winfo))->snr : 0;
		__entry->rate = (winfo) ? ((struct sc_capwap_ieee80211_frame_info *)(winfo))->rate : 0;
	),

	TP_printk(
		SESSION_PR_FMT " radio:%d binding:%d" SKB_PR_FMT
		"radioaddr:%*phC rssid:%d snr:%d rate:%d",
		SESSION_PR_ARG, __entry->radioid, __entry->binding, SKB_PR_ARG,
		min(__entry->radioaddrlength, 8), __entry->radioaddr,
		__entry->rssi, __entry->snr, __entry->rate
	)
);

TRACE_EVENT(sc_capwap_setradiomacaddress,
	TP_PROTO(uint8_t *bssid),

	TP_ARGS(bssid),

	TP_STRUCT__entry(
		BSSID_ENTRY
	),

	TP_fast_assign(
		BSSID_ASSIGN;
	),

	TP_printk(BSSID_PR_FMT, BSSID_PR_ARG)
);

TRACE_EVENT(sc_capwap_setwinfo_frameinfo,
	TP_PROTO(uint8_t rssi,
		 uint8_t snr,
		 uint16_t rate),

	TP_ARGS(rssi, snr, rate),

	TP_STRUCT__entry(
		__field(u8, rssi)
		__field(u8, snr)
		__field(u16, rate)
	),

	TP_fast_assign(
		__entry->rssi = rssi;
		__entry->snr = snr;
		__entry->rate = rate;
	),

	TP_printk(
		" rssid:%d snr:%d rate:%d",
		__entry->rssi, __entry->snr, __entry->rate
	)
);

TRACE_EVENT(sc_capwap_setwinfo_destwlans,
	TP_PROTO(uint16_t wlanidbitmap),

	TP_ARGS(wlanidbitmap),

	TP_STRUCT__entry(
		__field(u16, wlanidbitmap)
	),
	TP_fast_assign(
		__entry->wlanidbitmap = wlanidbitmap;
	),

	TP_printk(" id:%04x", __entry->wlanidbitmap)
);

/* capwap_private.c */

TRACE_EVENT(sc_capwap_resetsession,
	TP_PROTO(struct sc_capwap_session *session),

	TP_ARGS(session),

	TP_STRUCT__entry(
		SESSION_ENTRY
	),

	TP_fast_assign(
		SESSION_ASSIGN;
	),

	TP_printk(SESSION_PR_FMT, SESSION_PR_ARG)
);

TRACE_EVENT(sc_capwap_sendkeepalive,
	TP_PROTO(struct sc_capwap_session *session),

	TP_ARGS(session),

	TP_STRUCT__entry(
		SESSION_ENTRY
	),

	TP_fast_assign(
		SESSION_ASSIGN;
	),

	TP_printk(SESSION_PR_FMT, SESSION_PR_ARG)
);

TRACE_EVENT(sc_capwap_send,
	TP_PROTO(struct sc_capwap_session *session),

	TP_ARGS(session),

	TP_STRUCT__entry(
		SESSION_ENTRY
	),

	TP_fast_assign(
		SESSION_ASSIGN;
	),

	TP_printk(SESSION_PR_FMT, SESSION_PR_ARG)
);

TRACE_EVENT(sc_send_80211,
	TP_PROTO(struct sk_buff *skb, struct net_device *dev),

	    TP_ARGS(skb, dev),

	TP_STRUCT__entry(
		SKB_ENTRY
		__array(char, dev_name, 32)
	),

	TP_fast_assign(
		SKB_ASSIGN;
		strlcpy(__entry->dev_name, dev->name, 32);
	),

	TP_printk(" %s" SKB_PR_FMT, __entry->dev_name, SKB_PR_ARG)
);

TRACE_EVENT(sc_capwap_parsingdatapacket,
	TP_PROTO(struct sc_capwap_session *session,
		 struct sk_buff *skb),

	TP_ARGS(session, skb),

	TP_STRUCT__entry(
		SESSION_ENTRY
		SKB_ENTRY
	),

	TP_fast_assign(
		SESSION_ASSIGN;
		SKB_ASSIGN;
	),

	TP_printk(
		SESSION_PR_FMT SKB_PR_FMT,
		SESSION_PR_ARG, SKB_PR_ARG
	)
);

#endif /* !__CAPWAP_DRIVER_TRACE_H || TRACE_HEADER_MULTI_READ */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE capwap-trace
#include <trace/define_trace.h>
