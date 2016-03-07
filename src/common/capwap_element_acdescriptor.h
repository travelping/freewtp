#ifndef __CAPWAP_ELEMENT_ACDESCRIPTOR_HEADER__
#define __CAPWAP_ELEMENT_ACDESCRIPTOR_HEADER__

#define CAPWAP_ELEMENT_ACDESCRIPTION				1

#define CAPWAP_ACDESC_SECURITY_PRESHARED_KEY		0x04
#define CAPWAP_ACDESC_SECURITY_X509_CERT			0x02
#define CAPWAP_ACDESC_SECURITY_MASK					0x06

#define CAPWAP_ACDESC_RMACFIELD_SUPPORTED			1
#define CAPWAP_ACDESC_RMACFIELD_NOTSUPPORTED		2

#define CAPWAP_ACDESC_DTLS_DATA_CHANNEL_ENABLED		0x04
#define CAPWAP_ACDESC_CLEAR_DATA_CHANNEL_ENABLED	0x02
#define CAPWAP_ACDESC_DTLS_POLICY_MASK				0x06

struct capwap_acdescriptor_element {
	uint16_t stations;
	uint16_t stationlimit;
	uint16_t activewtp;
	uint16_t maxwtp;
	uint8_t security;
	uint8_t rmacfield;
	uint8_t dtlspolicy;
	struct capwap_array* descsubelement;
};

#define CAPWAP_ACDESC_SUBELEMENT_HARDWAREVERSION			4
#define CAPWAP_ACDESC_SUBELEMENT_SOFTWAREVERSION			5
#define CAPWAP_ACDESC_SUBELEMENT_MAXDATA					1024

struct capwap_acdescriptor_desc_subelement {
	uint32_t vendor;
	uint16_t type;
	uint16_t length;
	uint8_t* data;
};

extern const struct capwap_message_elements_ops capwap_element_acdescriptor_ops;

#endif /* __CAPWAP_ELEMENT_ACDESCRIPTOR_HEADER__ */
