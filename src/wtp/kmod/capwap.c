#include "config.h"
#include <linux/module.h>
#include <linux/ieee80211.h>
#include "socket.h"
#include "capwap.h"
#include "nlsmartcapwap.h"
#include "netlinkapp.h"

/* */
#define TIMEOUT_PACKET					10

/* */
union capwap_addr sc_localaddr;

/* */
static void sc_capwap_fragment_free(struct sc_capwap_fragment* fragment) {
	TRACEKMOD("### sc_capwap_fragment_free\n");

	/* */
	list_del(&fragment->lru_list);
	fragment->flags = 0;

	/* Free socket buffer */
	while (fragment->fragments) {
		struct sk_buff* next = fragment->fragments->next;

		kfree_skb(fragment->fragments);
		fragment->fragments = next;
	}
}

/* */
static void sc_capwap_defrag_evictor(struct sc_capwap_session* session, ktime_t now) {
	ktime_t delta;
	unsigned long flags;
	struct sc_capwap_fragment* fragment;

	TRACEKMOD("### sc_capwap_defrag_evictor\n");

	/* */
	if (now.tv64 == 0) {
		TRACEKMOD("*** Get time\n");
		now = ktime_get();
	}

	/* Remove last old fragment */
	if (!list_empty(&session->fragments.lru_list)) {
		spin_lock_irqsave(&session->fragments.lock, flags);

		fragment = list_first_entry(&session->fragments.lru_list, struct sc_capwap_fragment, lru_list);
		if (fragment) {
			delta = ktime_sub(now, fragment->tstamp);
			if ((delta.tv64 < 0) || (delta.tv64 > NSEC_PER_SEC)) {
				TRACEKMOD("*** Expired fragment %hu\n", fragment->fragmentid);

				/* Reset fragment */
				sc_capwap_fragment_free(fragment);
			}
		}

		spin_unlock_irqrestore(&session->fragments.lock, flags);
	}
}

/* */
static struct sk_buff* sc_capwap_reasm(struct sc_capwap_fragment* fragment) {
	int len;
	int offset;
	struct sk_buff* skb;
	struct sk_buff* skbfrag;
	struct sc_capwap_header* header;

	/* */
	skbfrag = fragment->fragments;
	len = GET_HLEN_HEADER((struct sc_capwap_header*)skbfrag->data) * 4;

	/* Create new packet */
	skb = alloc_skb(len + fragment->totallength, GFP_KERNEL);
	if (!skb) {
		return NULL;
	}

	/* The first capwap header is header of reassembled packet without fragment field */
	header = (struct sc_capwap_header*)skb_put(skb, len);
	memcpy(header, skb->data, len);

	SET_FLAG_F_HEADER(header, 0);
	SET_FLAG_L_HEADER(header, 0);
	header->frag_id = (__be16)0;
	header->frag_off = (__be16)0;

	/* Copy body */
	while (skbfrag) {
		offset = GET_HLEN_HEADER((struct sc_capwap_header*)skbfrag->data) * 4;
		len = skb->len - offset;

		/* */
		memcpy(skb_put(skb, len), skb->data + offset, len);
		skbfrag = skbfrag->next;
	}

	return skb;
}

/* */
static struct sk_buff* sc_capwap_defrag(struct sc_capwap_session* session, struct sk_buff* skb) {
	unsigned long flags;
	uint16_t headersize;
	uint16_t frag_id;
	struct sk_buff* prev;
	struct sk_buff* next;
	struct sc_capwap_fragment* fragment;
	struct sc_skb_capwap_cb* cb;
	struct sk_buff* skb_defrag = NULL;
	struct sc_capwap_header* header = (struct sc_capwap_header*)skb->data;

	TRACEKMOD("### sc_capwap_defrag\n");

	/* */
	headersize = GET_HLEN_HEADER(header) * 4;
	if (skb->len < headersize) {
		goto error;
	}

	/* */
	frag_id = be16_to_cpu(header->frag_id);

	/* */
	cb = CAPWAP_SKB_CB(skb);
	cb->flags |= SKB_CAPWAP_FLAG_FRAGMENT;
	cb->frag_offset = be16_to_cpu(header->frag_off);
	cb->frag_length = skb->len - headersize;

	/* */
	spin_lock_irqsave(&session->fragments.lock, flags);

	/* Get fragment */
	fragment = &session->fragments.queues[frag_id % CAPWAP_FRAGMENT_QUEUE];
	if ((fragment->flags & CAPWAP_FRAGMENT_ENABLE) && (fragment->fragmentid != frag_id)) {
		goto error2;	/* Queue fragment busy*/
	}

	/* Init fragment */
	if (!(fragment->flags & CAPWAP_FRAGMENT_ENABLE)) {
		fragment->flags = CAPWAP_FRAGMENT_ENABLE;
		fragment->fragmentid = frag_id;
		fragment->fragments = NULL;
		fragment->lastfragment = NULL;
		fragment->recvlength = 0;
		fragment->totallength = 0;
		list_add_tail(&fragment->lru_list, &session->fragments.lru_list);
	}

	/* Search fragment position */
	prev = fragment->lastfragment;
	if (!prev) {
		next = NULL;
	} else if (CAPWAP_SKB_CB(prev)->frag_offset < cb->frag_offset) {
		if ((CAPWAP_SKB_CB(prev)->frag_offset + CAPWAP_SKB_CB(prev)->frag_length) < cb->frag_offset) {
			next = NULL;
		} else {
			sc_capwap_fragment_free(fragment);
			goto error2;	/* Overlap error */
		}
	} else {
		prev = NULL;
		for (next = fragment->fragments; next != NULL; next = next->next) {
			struct sc_skb_capwap_cb* next_cb = CAPWAP_SKB_CB(next);

			if (next_cb->frag_offset < cb->frag_offset) {
				if ((next_cb->frag_offset + next_cb->frag_length) < cb->frag_offset) {
					break;
				} else {
					sc_capwap_fragment_free(fragment);
					goto error2;	/* Overlap error */
				}
			}

			prev = next;
		}
	}

	/* Insert fragment */
	skb->prev = NULL;
	skb->next = next;
	if (!next) {
		fragment->lastfragment = skb;
	}

	if (prev) {
		prev->next = skb;
	} else {
		fragment->fragments = skb;
	}

	/* Update size */
	fragment->recvlength += cb->frag_length;
	if (IS_FLAG_L_HEADER(header)) {
		fragment->totallength = cb->frag_offset + cb->frag_length;
		fragment->flags |= CAPWAP_FRAGMENT_LAST;
	}

	/* Check if receive all fragment */
	if ((fragment->flags & CAPWAP_FRAGMENT_LAST) && (fragment->recvlength == fragment->totallength)) {
		skb_defrag = sc_capwap_reasm(fragment);

		/* Free fragment complete */
		sc_capwap_fragment_free(fragment);
	} else {
		/* Update timeout */
		fragment->tstamp = skb->tstamp;
		if (fragment->tstamp.tv64 == 0) {
			fragment->tstamp = ktime_get();
		}

		/* Set LRU timeout */
		if (!list_is_last(&fragment->lru_list, &session->fragments.lru_list)) {
			list_move_tail(&fragment->lru_list, &session->fragments.lru_list);
		}
	}

	spin_unlock_irqrestore(&session->fragments.lock, flags);

	return skb_defrag;

error2:
	spin_unlock_irqrestore(&session->fragments.lock, flags);

error:
	kfree_skb(skb);
	return NULL;
}

/* */
int sc_capwap_bind(union capwap_addr* sockaddr) {
	int ret;

	TRACEKMOD("### sc_capwap_bind\n");

	/* */
	ret = sc_socket_bind(sockaddr);
	if (ret) {
		return ret;
	}

	memcpy(&sc_localaddr, sockaddr, sizeof(union capwap_addr));
	return 0;
}

/* */
void sc_capwap_initsession(struct sc_capwap_session* session) {
	TRACEKMOD("### sc_capwap_initsession\n");

	INIT_LIST_HEAD(&session->list);
	spin_lock_init(&session->fragmentid_lock);

	/* Defragment packets */
	memset(&session->fragments, 0, sizeof(struct sc_capwap_fragment_queue));
	INIT_LIST_HEAD(&session->fragments.lru_list);
	spin_lock_init(&session->fragments.lock);
}

/* */
void sc_capwap_freesession(struct sc_capwap_session* session) {
	struct sc_capwap_fragment* temp;
	struct sc_capwap_fragment* fragment;

	TRACEKMOD("### sc_capwap_freesession\n");

	/* Free socket buffers */
	list_for_each_entry_safe(fragment, temp, &session->fragments.lru_list, lru_list) {
		sc_capwap_fragment_free(fragment);
	}
}

/* */
uint16_t sc_capwap_newfragmentid(struct sc_capwap_session* session) {
	uint16_t fragmentid;
	unsigned long flags;

	TRACEKMOD("### sc_capwap_newfragmentid\n");

	spin_lock_irqsave(&session->fragmentid_lock, flags);
	fragmentid = session->fragmentid++;
	spin_unlock_irqrestore(&session->fragmentid_lock, flags);

	return fragmentid;
}

/* */
int sc_capwap_createkeepalive(struct sc_capwap_sessionid_element* sessionid, uint8_t* buffer, int size) {
	int length;
	struct sc_capwap_header* header;
	struct sc_capwap_data_message* dataheader;
	struct sc_capwap_message_element* msgelement;

	TRACEKMOD("### sc_capwap_createkeepalive\n");

	/* */
	if (size < CAPWAP_KEEP_ALIVE_MAX_SIZE) {
		return -ENOMEM;
	}

	/* Preamble CAPWAP header */
	header = (struct sc_capwap_header*)buffer;
	length = sizeof(struct sc_capwap_header);
	buffer += sizeof(struct sc_capwap_header);

	memset(header, 0, sizeof(struct sc_capwap_header));
	SET_VERSION_HEADER(header, CAPWAP_PROTOCOL_VERSION);
	SET_TYPE_HEADER(header, CAPWAP_PREAMBLE_HEADER);
	SET_HLEN_HEADER(header, sizeof(struct sc_capwap_header) / 4);
	SET_WBID_HEADER(header, CAPWAP_WIRELESS_BINDING_IEEE80211);
	SET_FLAG_K_HEADER(header, 1);

	/* CAPWAP Data header */
	dataheader = (struct sc_capwap_data_message*)buffer;
	length += sizeof(struct sc_capwap_data_message);
	buffer += sizeof(struct sc_capwap_data_message);

	dataheader->length = cpu_to_be16(sizeof(struct sc_capwap_data_message) + sizeof(struct sc_capwap_message_element) + sizeof(struct sc_capwap_sessionid_element));

	/* CAPWAP Keep-Alive Message Element */
	msgelement = (struct sc_capwap_message_element*)buffer;
	length += sizeof(struct sc_capwap_message_element);
	buffer += sizeof(struct sc_capwap_message_element);

	msgelement->type = cpu_to_be16(CAPWAP_ELEMENT_SESSIONID);
	msgelement->length = cpu_to_be16(sizeof(struct sc_capwap_sessionid_element));

	/* Session ID */
	memcpy(buffer, sessionid, sizeof(struct sc_capwap_sessionid_element));
	length += sizeof(struct sc_capwap_sessionid_element);

	return length;
}

/* */
int sc_capwap_parsingpacket(struct sc_capwap_session* session, const union capwap_addr* sockaddr, struct sk_buff* skb) {
	int length;
	uint16_t headersize;
	struct sc_capwap_data_message* dataheader;
	struct sc_capwap_message_element* message;
	struct sc_capwap_header* header = (struct sc_capwap_header*)skb->data;

	TRACEKMOD("### sc_capwap_parsingpacket\n");

	/* Linearize socket buffer */
	if (skb_linearize(skb)) {
		TRACEKMOD("*** Unable to linearize packet\n");
		return -EINVAL;
	}

	/* Check header */
	if (skb->len < sizeof(struct sc_capwap_header)) {
		TRACEKMOD("*** Invalid capwap header length\n");
		return -EINVAL;
	} else if (GET_VERSION_HEADER(header) != CAPWAP_PROTOCOL_VERSION) {
		TRACEKMOD("*** Invalid capwap header version\n");
		return -EINVAL;
	} else if (GET_TYPE_HEADER(header) != CAPWAP_PREAMBLE_HEADER) {
		TRACEKMOD("*** Packet is encrypted\n");
		return -EINVAL;		/* Accept only plain packet */
	}

	/* Cleaning old fragments */
	if (session) {
		sc_capwap_defrag_evictor(session, skb->tstamp);
	}

	/* */
	if (IS_FLAG_K_HEADER(header)) {
		/* Keep alive can not fragment */
		if (IS_FLAG_F_HEADER(header)) {
			TRACEKMOD("*** Keep alive can not fragment\n");
			return -EINVAL;
		}

		/* */
		length = skb->len;
		headersize = GET_HLEN_HEADER(header) * 4;
		if (length < (headersize + sizeof(struct sc_capwap_data_message))) {
			TRACEKMOD("*** Invalid capwap data header length\n");
			return -EINVAL;
		}

		/* Data message */
		length -= headersize;
		dataheader = (struct sc_capwap_data_message*)(((uint8_t*)header) + headersize);
		headersize = ntohs(dataheader->length);
		if (length < headersize) {
			TRACEKMOD("*** Capwap data header length mismatch\n");
			return -EINVAL;
		}

		/* Message elements */
		headersize -= sizeof(struct sc_capwap_data_message);
		message = (struct sc_capwap_message_element*)(((uint8_t*)dataheader) + sizeof(struct sc_capwap_data_message));
		while (headersize > 0) {
			uint16_t msglength = ntohs(message->length);
			if (headersize < (msglength + sizeof(struct sc_capwap_message_element))) {
				TRACEKMOD("*** Invalid capwap message element length\n");
				return -EINVAL;
			}

			/* */
			if ((ntohs(message->type) == CAPWAP_ELEMENT_SESSIONID) && (msglength == sizeof(struct sc_capwap_sessionid_element))) {
				struct sc_capwap_sessionid_element* sessionid = (struct sc_capwap_sessionid_element*)(((uint8_t*)message) + sizeof(struct sc_capwap_message_element));

				if (!session) {
					session = sc_capwap_recvunknownkeepalive(sockaddr, sessionid);
					if (!session) {
						TRACEKMOD("*** Receive unknown keep alive without valid session\n");
						return -EINVAL;
					}
				} else if (memcmp(&session->sessionid, sessionid, sizeof(struct sc_capwap_sessionid_element))) {
					TRACEKMOD("*** Session id mismatch\n");
					return -EINVAL;
				}

				/* Session found */
				sc_netlink_notify_recv_keepalive(sockaddr, sessionid);

				/* Parsing complete */
				kfree_skb(skb);
				return 0;
			}

			/* Next message element */
			msglength += sizeof(struct sc_capwap_message_element);
			message = (struct sc_capwap_message_element*)(((uint8_t*)message) + msglength);
			headersize -= msglength;
		}
	} else if (session) {
		if (IS_FLAG_F_HEADER(header)) {
			skb = sc_capwap_defrag(session, skb);
			if (!skb) {
				return 0;
			}

			/* Get new header info */
			header = (struct sc_capwap_header*)skb->data;
		}

		/* Parsing data/management packet */
		if (!IS_FLAG_T_HEADER(header)) {
			sc_capwap_parsingdatapacket(session, skb);
		} else if (GET_WBID_HEADER(header) == CAPWAP_WIRELESS_BINDING_IEEE80211) {
			struct ieee80211_hdr* hdr = (struct ieee80211_hdr*)(skb->data + GET_HLEN_HEADER(header) * 4);

			if (ieee80211_is_data_present(hdr->frame_control)) {
				sc_capwap_parsingdatapacket(session, skb);
			} else if (ieee80211_is_mgmt(hdr->frame_control) || ieee80211_is_ctl(hdr->frame_control)) {
				sc_capwap_parsingmgmtpacket(session, skb);
			}
		}

		/* Parsing complete */
		kfree_skb(skb);
		return 0;
	}

	return -EINVAL;
}

/* */
int sc_capwap_forwarddata(struct sc_capwap_session* session, uint8_t radioid, uint8_t binding, struct sk_buff* skb, uint32_t flags, struct sc_capwap_radio_addr* radioaddr, int radioaddrlength, struct sc_capwap_wireless_information* winfo, int winfolength) {
	int size;
	int length;
	int reserve;
	int headroom;
	int requestfragment;
	__be16 fragmentid = 0;
	int fragmentoffset = 0;
	struct sc_capwap_header* header;
	struct sk_buff* clone = NULL;
	int packetlength = skb->len;

	TRACEKMOD("### sc_capwap_forwarddata\n");

	/* Check headroom */
	headroom = skb_headroom(skb);
	reserve = sizeof(struct sc_capwap_header) + radioaddrlength + winfolength;
	if (skb_is_nonlinear(skb) || (headroom < reserve)) {
		printk("*** Expand socket buffer\n");
		clone = skb_copy_expand(skb, max_t(int, headroom, reserve), skb_tailroom(skb), GFP_KERNEL);
		if (!clone) {
			printk("*** Unable to expand socket buffer\n");
			return -ENOMEM;
		}

		skb = clone;
	}

	/* Check MTU */
	requestfragment = (((packetlength + reserve) > session->mtu) ? 1 : 0);
	if (requestfragment) {
		fragmentid = cpu_to_be16(sc_capwap_newfragmentid(session));
	}

	/* */
	header = (struct sc_capwap_header*)skb_push(skb, sizeof(struct sc_capwap_header) + radioaddrlength + winfolength);
	while (packetlength > 0) {
		memset(header, 0, sizeof(struct sc_capwap_header));
		SET_VERSION_HEADER(header, CAPWAP_PROTOCOL_VERSION);
		SET_TYPE_HEADER(header, CAPWAP_PREAMBLE_HEADER);
		SET_WBID_HEADER(header, binding);
		SET_RID_HEADER(header, radioid);
		SET_FLAG_T_HEADER(header, ((flags & NLSMARTCAPWAP_FLAGS_TUNNEL_8023) ? 0 : 1));

		if (!fragmentoffset) {
			uint8_t* headeroption = (uint8_t*)header + sizeof(struct sc_capwap_header);

			if (radioaddr) {
				SET_FLAG_M_HEADER(header, 1);
				memcpy(headeroption, radioaddr, radioaddrlength);
				headeroption += radioaddrlength;
			}

			if (winfo) {
				SET_FLAG_W_HEADER(header, 1);
				memcpy(headeroption, winfo, winfolength);
				headeroption += winfolength;
			}

			size = sizeof(struct sc_capwap_header) + radioaddrlength + winfolength;
			SET_HLEN_HEADER(header, size / 4);
		} else {
			size = sizeof(struct sc_capwap_header);
			SET_HLEN_HEADER(header, size / 4);
		}

		/* Calculate body size */
		length = session->mtu - size;
		if (packetlength <= length) {
			length = packetlength;
		} else if (requestfragment) {
			length -= length % 8;		/* Capwap fragment size is module 8 */
		} else {
			break;
		}

		/* Fragment options */
		if (requestfragment) {
			SET_FLAG_F_HEADER(header, 1);
			if (packetlength == length) {
				SET_FLAG_L_HEADER(header, 1);
			}

			header->frag_id = fragmentid;
			header->frag_off = cpu_to_be16(fragmentoffset);
		}

		/* Send packet */
		if (sc_socket_send(SOCKET_UDP, (uint8_t*)header, (size + length), &session->peeraddr) < 0) {
			break;
		}

		/* */
		header = (struct sc_capwap_header*)((uint8_t*)header + (size + length));
		fragmentoffset += length;
		packetlength -= length;
	}

	if (clone) {
		kfree_skb(clone);
	}

	return (!packetlength ? 0 : -EIO);
}

/* */
void sc_capwap_sessionid_printf(const struct sc_capwap_sessionid_element* sessionid, char* string) {
	int i;
	char* pos = string;

	for (i = 0; i < 16; i++) {
		snprintf(pos, 3, "%02x", sessionid->id[i]);
		pos += 2;
	}

	*pos = 0;
}

/* */
struct sc_capwap_radio_addr* sc_capwap_setradiomacaddress(uint8_t* buffer, int size, uint8_t* bssid) {
	struct sc_capwap_radio_addr* radioaddr;
	struct sc_capwap_macaddress_eui48* addr;

	TRACEKMOD("### sc_capwap_setwirelessinformation\n");

	memset(buffer, 0, size);

	radioaddr = (struct sc_capwap_radio_addr*)buffer;
	radioaddr->length = MACADDRESS_EUI48_LENGTH;

	addr = (struct sc_capwap_macaddress_eui48*)(buffer + sizeof(struct sc_capwap_radio_addr));
	memcpy(addr->addr, bssid, MACADDRESS_EUI48_LENGTH);

	return radioaddr;
}

/* */
struct sc_capwap_wireless_information* sc_capwap_setwirelessinformation(uint8_t* buffer, int size, uint8_t rssi, uint8_t snr, uint16_t rate) {
	struct sc_capwap_wireless_information* winfo;
	struct sc_capwap_ieee80211_frame_info* frameinfo;

	TRACEKMOD("### sc_capwap_setwirelessinformation\n");

	memset(buffer, 0, size);

	winfo = (struct sc_capwap_wireless_information*)buffer;
	winfo->length = sizeof(struct sc_capwap_ieee80211_frame_info);

	frameinfo = (struct sc_capwap_ieee80211_frame_info*)(buffer + sizeof(struct sc_capwap_wireless_information));
	frameinfo->rssi = rssi;
	frameinfo->snr = snr;
	frameinfo->rate = cpu_to_be16(rate);

	return winfo;
}
