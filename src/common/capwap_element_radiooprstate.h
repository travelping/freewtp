#ifndef __CAPWAP_ELEMENT_RADIOOPRSTATE_HEADER__
#define __CAPWAP_ELEMENT_RADIOOPRSTATE_HEADER__

#define CAPWAP_ELEMENT_RADIOOPRSTATE		32

struct capwap_radiooprstate_element {
	unsigned char radioid;
	unsigned char state;
	unsigned char cause;
};

#define CAPWAP_RADIO_OPERATIONAL_STATE_ENABLED				1
#define CAPWAP_RADIO_OPERATIONAL_STATE_DISABLED				2

#define CAPWAP_RADIO_OPERATIONAL_CAUSE_NORMAL				0
#define CAPWAP_RADIO_OPERATIONAL_CAUSE_RADIOFAILURE			1
#define CAPWAP_RADIO_OPERATIONAL_CAUSE_SOFTWAREFAILURE		2
#define CAPWAP_RADIO_OPERATIONAL_CAUSE_ADMINSET				3

struct capwap_message_element* capwap_radiooprstate_element_create(void* data, unsigned long length);
int capwap_radiooprstate_element_validate(struct capwap_message_element* element);
void* capwap_radiooprstate_element_parsing(struct capwap_message_element* element);
void capwap_radiooprstate_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_RADIOOPRSTATE_ELEMENT(x)		({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_RADIOOPRSTATE);	\
														f->create(x, sizeof(struct capwap_radiooprstate_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_RADIOOPRSTATE_HEADER__ */
