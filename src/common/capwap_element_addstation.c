#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |     Length    |          MAC Address ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  VLAN Name...
+-+-+-+-+-+-+-+-+

Type:   8 for Add Station

Length:   >= 8

********************************************************************/

/* */
static void capwap_addstation_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_addstation_element* element = (struct capwap_addstation_element*)data;

	ASSERT(data != NULL);
	ASSERT(IS_VALID_RADIOID(element->radioid));
	ASSERT(IS_VALID_MACADDRESS_LENGTH(element->length));

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->length);
	func->write_block(handle, element->address, element->length);
	if (element->vlan && *element->vlan) {
		unsigned short length = strlen((char*)element->vlan);

		ASSERT(length <= CAPWAP_ADDSTATION_VLAN_MAX_LENGTH);

		func->write_block(handle, element->vlan, length);
	}
}

/* */
static void* capwap_addstation_element_clone(void* data) {
	struct capwap_addstation_element* cloneelement;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_addstation_element));
	if (cloneelement->length > 0) {
		cloneelement->address = capwap_clone(((struct capwap_addstation_element*)data)->address, cloneelement->length);
	}

	if (cloneelement->vlan) {
		cloneelement->vlan = (uint8_t*)capwap_duplicate_string((char*)((struct capwap_addstation_element*)data)->vlan);
	}

	return cloneelement;
}

/* */
static void capwap_addstation_element_free(void* data) {
	struct capwap_addstation_element* element = (struct capwap_addstation_element*)data;

	ASSERT(data != NULL);

	if (element->vlan) {
		capwap_free(element->vlan);
	}

	if (element->address) {
		capwap_free(element->address);
	}

	capwap_free(element);
}

/* */
static void* capwap_addstation_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_addstation_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 8) {
		log_printf(LOG_DEBUG, "Invalid Add Station element: underbuffer");
		return NULL;
	}

	length -= 2;

	/* */
	data = (struct capwap_addstation_element*)capwap_alloc(sizeof(struct capwap_addstation_element));
	memset(data, 0, sizeof(struct capwap_addstation_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->length);

	if (!IS_VALID_RADIOID(data->radioid)) {
		capwap_addstation_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Add Station element: invalid radio");
		return NULL;
	} else if (!IS_VALID_MACADDRESS_LENGTH(data->length) || (length < data->length)) {
		capwap_addstation_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Add Station element: invalid length");
		return NULL;
	}

	data->address = (uint8_t*)capwap_alloc(data->length);
	func->read_block(handle, data->address, data->length);
	length -= data->length;

	if (length > 0) {
		if (length <= CAPWAP_ADDSTATION_VLAN_MAX_LENGTH) {
			data->vlan = (uint8_t*)capwap_alloc(length + 1);
			func->read_block(handle, data->vlan, length);
			data->vlan[length] = 0;
		} else {
			capwap_addstation_element_free((void*)data);
			log_printf(LOG_DEBUG, "Invalid Add Station element: invalid vlan");
			return NULL;
		}
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_addstation_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_addstation_element_create,
	.parse = capwap_addstation_element_parsing,
	.clone = capwap_addstation_element_clone,
	.free = capwap_addstation_element_free
};
