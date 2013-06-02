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

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->length);
	func->write_block(handle, element->address, element->length);
	if (element->vlan && *element->vlan) {
		func->write_block(handle, element->vlan, strlen((char*)element->vlan));
	}
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
		capwap_logging_debug("Invalid Add Station element");
		return NULL;
	}

	length -= 2;

	/* */
	data = (struct capwap_addstation_element*)capwap_alloc(sizeof(struct capwap_addstation_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_addstation_element));

	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->length);

	if (length < data->length) {
		capwap_addstation_element_free((void*)data);
		capwap_logging_debug("Invalid Add Station element");
		return NULL;
	}

	data->address = (uint8_t*)capwap_alloc(data->length);
	if (!data->address) {
		capwap_outofmemory();
	}

	func->read_block(handle, data->address, data->length);
	length -= data->length;

	if (length) {
		data->vlan = (uint8_t*)capwap_alloc(length + 1);
		if (!data->vlan) {
			capwap_outofmemory();
		}
	
		func->read_block(handle, data->vlan, length);
		data->vlan[length] = 0;
	}

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_addstation_ops = {
	.create_message_element = capwap_addstation_element_create,
	.parsing_message_element = capwap_addstation_element_parsing,
	.free_parsed_message_element = capwap_addstation_element_free
};
