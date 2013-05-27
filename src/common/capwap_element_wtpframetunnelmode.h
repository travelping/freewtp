#ifndef __CAPWAP_ELEMENT_WTPFRAMETUNNELMODE_HEADER__
#define __CAPWAP_ELEMENT_WTPFRAMETUNNELMODE_HEADER__

#define CAPWAP_ELEMENT_WTPFRAMETUNNELMODE		41

#define CAPWAP_WTP_FRAME_TUNNEL_MODE_MASK		0x0e
#define CAPWAP_WTP_NATIVE_FRAME_TUNNEL			0x08
#define CAPWAP_WTP_8023_FRAME_TUNNEL			0x04
#define CAPWAP_WTP_LOCAL_BRIDGING				0x02

struct capwap_wtpframetunnelmode_element {
	uint8_t mode;
};

extern struct capwap_message_elements_ops capwap_element_wtpframetunnelmode_ops;

#endif /* __CAPWAP_ELEMENT_WTPFRAMETUNNELMODE_HEADER__ */
