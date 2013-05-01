#ifndef __CAPWAP_ELEMENT_WTPFRAMETUNNELMODE_HEADER__
#define __CAPWAP_ELEMENT_WTPFRAMETUNNELMODE_HEADER__

#define CAPWAP_ELEMENT_WTPFRAMETUNNELMODE		41

struct capwap_wtpframetunnelmode_element {
	unsigned char mode;
};

#define CAPWAP_WTP_FRAME_TUNNEL_MODE_MASK		0x0e
#define CAPWAP_WTP_NATIVE_FRAME_TUNNEL			0x08
#define CAPWAP_WTP_8023_FRAME_TUNNEL			0x04
#define CAPWAP_WTP_LOCAL_BRIDGING				0x02

struct capwap_message_element* capwap_wtpframetunnelmode_element_create(void* data, unsigned long datalength);
int capwap_wtpframetunnelmode_element_validate(struct capwap_message_element* element);
void* capwap_wtpframetunnelmode_element_parsing(struct capwap_message_element* element);
void capwap_wtpframetunnelmode_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_WTPFRAMETUNNELMODE_ELEMENT(x)			({	\
																struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_WTPFRAMETUNNELMODE);	\
																f->create(x, sizeof(struct capwap_wtpframetunnelmode_element));	\
															})

#endif /* __CAPWAP_ELEMENT_WTPFRAMETUNNELMODE_HEADER__ */
