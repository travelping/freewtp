#include "config.h"
#include <linux/module.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <linux/ieee80211.h>
#include "socket.h"
#include "capwap.h"
#include "nlsmartcapwap.h"
#include "netlinkapp.h"

/* */
union capwap_addr sc_localaddr;

/* Ethernet-II snap header (RFC1042 for most EtherTypes) */
static unsigned char sc_rfc1042_header[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

/* Bridge-Tunnel header (for EtherTypes ETH_P_AARP and ETH_P_IPX) */
static unsigned char sc_bridge_tunnel_header[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };

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
	struct sc_capwap_fragment* fragment;
	struct list_head* list = &session->fragments.lru_list;

	TRACEKMOD("### sc_capwap_defrag_evictor\n");

	/* Light check without lock */
	if (!list_empty(list)) {
		spin_lock(&session->fragments.lock);

		/* Remove last old fragment */
		if (!list_empty(list)) {
			fragment = list_first_entry(list, struct sc_capwap_fragment, lru_list);
			delta = ktime_sub(now, fragment->tstamp);
			if ((delta.tv64 < -NSEC_PER_SEC) || (delta.tv64 > NSEC_PER_SEC)) {
				TRACEKMOD("*** Expired fragment %hu (%llu %llu)\n", fragment->fragmentid, now.tv64, fragment->tstamp.tv64);
				sc_capwap_fragment_free(fragment);
			}
		}

		spin_unlock(&session->fragments.lock);
	}
}

/* */
static struct sk_buff* sc_capwap_reasm(struct sc_capwap_fragment* fragment) {
	int len;
	int offset;
	struct sk_buff* skb;
	struct sk_buff* skbfrag;
	struct sc_capwap_header* header;

	TRACEKMOD("### sc_capwap_reasm\n");

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
	memcpy(header, skbfrag->data, len);

	SET_FLAG_F_HEADER(header, 0);
	SET_FLAG_L_HEADER(header, 0);
	header->frag_id = (__be16)0;
	header->frag_off = (__be16)0;

	/* Copy body */
	while (skbfrag) {
		offset = GET_HLEN_HEADER((struct sc_capwap_header*)skbfrag->data) * 4;
		len = skbfrag->len - offset;

		TRACEKMOD("*** Append fragment size %d\n", len);

		/* */
		memcpy(skb_put(skb, len), skbfrag->data + offset, len);
		skbfrag = skbfrag->next;
	}

	TRACEKMOD("*** Assemblate capwap data packet with total size %d\n", skb->len);

	return skb;
}

/* */
static struct sk_buff* sc_capwap_defrag(struct sc_capwap_session* session, struct sk_buff* skb) {
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
	spin_lock(&session->fragments.lock);
	TRACEKMOD("*** Fragment info: id %hu offset %hu length %hu\n", frag_id, cb->frag_offset, cb->frag_length);

	/* Get fragment */
	fragment = &session->fragments.queues[frag_id % CAPWAP_FRAGMENT_QUEUE];
	if ((fragment->flags & CAPWAP_FRAGMENT_ENABLE) && (fragment->fragmentid != frag_id)) {
		TRACEKMOD("*** Unable defrag, queue fragment busy\n");
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
		if ((CAPWAP_SKB_CB(prev)->frag_offset + CAPWAP_SKB_CB(prev)->frag_length) <= cb->frag_offset) {
			next = NULL;
		} else {
			sc_capwap_fragment_free(fragment);
			TRACEKMOD("*** Unable defrag, overlap error\n");
			goto error2;	/* Overlap error */
		}
	} else {
		prev = NULL;
		for (next = fragment->fragments; next != NULL; next = next->next) {
			struct sc_skb_capwap_cb* next_cb = CAPWAP_SKB_CB(next);

			if (next_cb->frag_offset == cb->frag_offset) {
				TRACEKMOD("*** Unable defrag, duplicate packet\n");
				goto error2;	/* Duplicate packet */
			} else if (next_cb->frag_offset > cb->frag_offset) {
				if ((cb->frag_offset + cb->frag_length) <= next_cb->frag_offset) {
					break;
				} else {
					sc_capwap_fragment_free(fragment);
					TRACEKMOD("*** Unable defrag, overlap error\n");
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
		TRACEKMOD("*** Fragment id %hu expire at %llu\n", frag_id, fragment->tstamp.tv64);

		/* Set LRU timeout */
		if (!list_is_last(&fragment->lru_list, &session->fragments.lru_list)) {
			list_move_tail(&fragment->lru_list, &session->fragments.lru_list);
		}
	}

	spin_unlock(&session->fragments.lock);

	return skb_defrag;

error2:
	spin_unlock(&session->fragments.lock);

error:
	kfree_skb(skb);
	return NULL;
}

/* */
static unsigned int sc_capwap_80211_hdrlen(__le16 fc) {
	unsigned int hdrlen = 24;

	TRACEKMOD("### sc_capwap_80211_hdrlen\n");

	if (ieee80211_is_data(fc)) {
		if (ieee80211_has_a4(fc)) {
			hdrlen = 30;
		}

		if (ieee80211_is_data_qos(fc)) {
			hdrlen += IEEE80211_QOS_CTL_LEN;
			if (ieee80211_has_order(fc)) {
				hdrlen += IEEE80211_HT_CTL_LEN;
			}
		}
	} else if (ieee80211_is_ctl(fc)) {
		if ((fc & cpu_to_le16(0x00E0)) == cpu_to_le16(0x00C0)) {
			hdrlen = 10;
		} else {
			hdrlen = 16;
		}
	}

	return hdrlen;
}

/* */
int sc_capwap_8023_to_80211(struct sk_buff* skb, const uint8_t* bssid) {
	uint16_t hdrlen;
	int head_need;
	struct ieee80211_hdr hdr;
	int skip_header_bytes;
	uint8_t* encaps_data;
	int encaps_len;
	struct ethhdr* eh = (struct ethhdr*)skb->data;
	uint16_t ethertype = ntohs(eh->h_proto);

	TRACEKMOD("### sc_capwap_8023_to_80211\n");

	/* IEEE 802.11 header */
	hdrlen = 24;
	hdr.frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA | IEEE80211_FCTL_FROMDS);
	memcpy(hdr.addr1, eh->h_dest, ETH_ALEN);
	memcpy(hdr.addr2, bssid, ETH_ALEN);
	memcpy(hdr.addr3, eh->h_source, ETH_ALEN);
	hdr.duration_id = 0;
	hdr.seq_ctrl = 0;

	/* */
	skip_header_bytes = ETH_HLEN;
	if ((ethertype == ETH_P_AARP) || (ethertype == ETH_P_IPX)) {
		encaps_data = sc_bridge_tunnel_header;
		encaps_len = sizeof(sc_bridge_tunnel_header);
		skip_header_bytes -= 2;
	} else if (ethertype >= ETH_P_802_3_MIN) {
		encaps_data = sc_rfc1042_header;
		encaps_len = sizeof(sc_rfc1042_header);
		skip_header_bytes -= 2;
	} else {
		encaps_data = NULL;
		encaps_len = 0;
	}

	/* Remove IEEE 802.3 header */
	skb_pull(skb, skip_header_bytes);

	/* Check headroom */
	head_need = hdrlen + encaps_len - skb_headroom(skb);
	if ((head_need > 0) || skb_cloned(skb)) {
		head_need = max(head_need, 0);
		if (head_need) {
			skb_orphan(skb);
		}

		TRACEKMOD("*** Expand headroom skb of: %d\n", head_need);
		if (pskb_expand_head(skb, head_need, 0, GFP_ATOMIC)) {
			return -ENOMEM;
		}

		skb->truesize += head_need;
	}

	/* Add LLC header */
	if (encaps_data) {
		memcpy(skb_push(skb, encaps_len), encaps_data, encaps_len);
	}

	/* Add IEEE 802.11 header */
	memcpy(skb_push(skb, hdrlen), &hdr, hdrlen);
	skb_reset_mac_header(skb);

	return 0;
}

/* */
int sc_capwap_80211_to_8023(struct sk_buff* skb) {
	struct ieee80211_hdr* hdr = (struct ieee80211_hdr*)skb->data;
	uint16_t hdrlen;
	uint16_t ethertype;
	uint8_t* payload;
	uint8_t dst[ETH_ALEN];
	uint8_t src[ETH_ALEN] __aligned(2);

	TRACEKMOD("### sc_capwap_80211_to_8023\n");

	/* */
	hdrlen = sc_capwap_80211_hdrlen(hdr->frame_control);
	memcpy(dst, ieee80211_get_DA(hdr), ETH_ALEN);
	memcpy(src, ieee80211_get_SA(hdr), ETH_ALEN);

	/* */
	if (!pskb_may_pull(skb, hdrlen + 8)) {
		return -1;
	}

	/* */
	payload = skb->data + hdrlen;
	ethertype = (payload[6] << 8) | payload[7];

	if (likely((ether_addr_equal(payload, sc_rfc1042_header) && (ethertype != ETH_P_AARP) && (ethertype != ETH_P_IPX)) || ether_addr_equal(payload, sc_bridge_tunnel_header))) {
		skb_pull(skb, hdrlen + 6);
		memcpy(skb_push(skb, ETH_ALEN), src, ETH_ALEN);
		memcpy(skb_push(skb, ETH_ALEN), dst, ETH_ALEN);
	} else {
		struct ethhdr *ehdr;
		__be16 len;

		skb_pull(skb, hdrlen);
		len = htons(skb->len);
		ehdr = (struct ethhdr *) skb_push(skb, sizeof(struct ethhdr));
		memcpy(ehdr->h_dest, dst, ETH_ALEN);
		memcpy(ehdr->h_source, src, ETH_ALEN);
		ehdr->h_proto = len;
	}

	return 0;
}

/* */
int sc_capwap_bind(struct net *net, union capwap_addr* sockaddr) {
	int ret;

	TRACEKMOD("### sc_capwap_bind\n");

	/* */
	ret = sc_socket_bind(net, sockaddr);
	if (ret) {
		return ret;
	}

	memcpy(&sc_localaddr, sockaddr, sizeof(union capwap_addr));
	return 0;
}

/* */
void sc_capwap_initsession(struct sc_capwap_session* session) {
	TRACEKMOD("### sc_capwap_initsession\n");

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

	TRACEKMOD("### sc_capwap_newfragmentid\n");

	spin_lock(&session->fragmentid_lock);
	fragmentid = session->fragmentid++;
	spin_unlock(&session->fragmentid_lock);

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
int sc_capwap_parsingpacket(struct sc_capwap_session* session,
			    const union capwap_addr* sockaddr,
			    struct sk_buff* skb) {
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
				sc_netlink_notify_recv_keepalive(session->net, sockaddr, sessionid);

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
		if (!skb->tstamp.tv64) {
			skb->tstamp = ktime_get();
		}

		/* Cleaning old fragments */
		sc_capwap_defrag_evictor(session, skb->tstamp);

		/* */
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

		return 0;
	}

	return -EINVAL;
}

/* */
int sc_capwap_forwarddata(struct sc_capwap_session* session, uint8_t radioid, uint8_t binding, struct sk_buff* skb, uint32_t flags, struct sc_capwap_radio_addr* radioaddr, int radioaddrlength, struct sc_capwap_wireless_information* winfo, int winfolength) {
	int err;
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
		TRACEKMOD("*** Copy socket buffer and expand headroom of: %d\n", (reserve - headroom));
		clone = skb_copy_expand(skb, max(headroom, reserve), skb_tailroom(skb), GFP_KERNEL);
		if (!clone) {
			TRACEKMOD("*** Unable to copy socket buffer\n");
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
		err = sc_socket_send(SOCKET_UDP, (uint8_t*)header, (size + length), &session->peeraddr);
		TRACEKMOD("*** Send packet result: %d\n", err);
		if (err < 0) {
			break;
		}

		/* */
		header = (struct sc_capwap_header*)(((uint8_t*)header + size + length) - sizeof(struct sc_capwap_header));
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

	addr = (struct sc_capwap_macaddress_eui48*)radioaddr->addr;
	memcpy(addr->addr, bssid, MACADDRESS_EUI48_LENGTH);

	return radioaddr;
}

/* */
struct sc_capwap_wireless_information* sc_capwap_setwinfo_frameinfo(uint8_t* buffer, int size, uint8_t rssi, uint8_t snr, uint16_t rate) {
	struct sc_capwap_wireless_information* winfo;
	struct sc_capwap_ieee80211_frame_info* frameinfo;

	TRACEKMOD("### sc_capwap_setwinfo_frameinfo\n");

	memset(buffer, 0, size);

	winfo = (struct sc_capwap_wireless_information*)buffer;
	winfo->length = sizeof(struct sc_capwap_ieee80211_frame_info);

	frameinfo = (struct sc_capwap_ieee80211_frame_info*)(buffer + sizeof(struct sc_capwap_wireless_information));
	frameinfo->rssi = rssi;
	frameinfo->snr = snr;
	frameinfo->rate = cpu_to_be16(rate);

	return winfo;
}

/* */
struct sc_capwap_wireless_information* sc_capwap_setwinfo_destwlans(uint8_t* buffer, int size, uint16_t wlanidbitmap) {
	struct sc_capwap_wireless_information* winfo;
	struct sc_capwap_destination_wlans* destwlans;

	TRACEKMOD("### sc_capwap_setwinfo_destwlans\n");

	memset(buffer, 0, size);

	winfo = (struct sc_capwap_wireless_information*)buffer;
	winfo->length = sizeof(struct sc_capwap_destination_wlans);

	destwlans = (struct sc_capwap_destination_wlans*)(buffer + sizeof(struct sc_capwap_wireless_information));
	destwlans->wlanidbitmap = cpu_to_be16(wlanidbitmap);

	return winfo;
}
