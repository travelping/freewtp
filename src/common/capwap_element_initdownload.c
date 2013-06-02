#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

Type:   27 for Initiate Download

Length:   0

********************************************************************/

/* */
static void capwap_initdownload_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
}

/* */
static void* capwap_initdownload_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_initdownload_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 0) {
		capwap_logging_debug("Invalid Initiate Download element");
		return NULL;
	}

	/* */
	data = (struct capwap_initdownload_element*)capwap_alloc(sizeof(struct capwap_initdownload_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_initdownload_element));

	return data;
}

/* */
static void capwap_initdownload_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_initdownload_ops = {
	.create_message_element = capwap_initdownload_element_create,
	.parsing_message_element = capwap_initdownload_element_parsing,
	.free_parsed_message_element = capwap_initdownload_element_free
};
