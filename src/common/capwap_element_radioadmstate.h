#ifndef __CAPWAP_ELEMENT_RADIOADMSTATE_HEADER__
#define __CAPWAP_ELEMENT_RADIOADMSTATE_HEADER__

#define CAPWAP_ELEMENT_RADIOADMSTATE		31

struct capwap_radioadmstate_element {
	unsigned char radioid;
	unsigned char state;
};

#define CAPWAP_RADIO_ADMIN_STATE_ENABLED		1
#define CAPWAP_RADIO_ADMIN_STATE_DISABLED		2

struct capwap_message_element* capwap_radioadmstate_element_create(void* data, unsigned long length);
int capwap_radioadmstate_element_validate(struct capwap_message_element* element);
void* capwap_radioadmstate_element_parsing(struct capwap_message_element* element);
void capwap_radioadmstate_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_RADIOADMSTATE_ELEMENT(x)		({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_RADIOADMSTATE);	\
														f->create(x, sizeof(struct capwap_radioadmstate_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_RADIOADMSTATE_HEADER__ */
