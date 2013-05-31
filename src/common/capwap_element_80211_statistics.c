#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |                   Reserved                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Tx Fragment Count                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Multicast Tx Count                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Failed Count                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Retry Count                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Multiple Retry Count                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Frame Duplicate Count                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       RTS Success Count                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       RTS Failure Count                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       ACK Failure Count                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Rx Fragment Count                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Multicast RX Count                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        FCS Error  Count                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Tx Frame Count                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Decryption Errors                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Discarded QoS Fragment Count                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Associated Station Count                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  QoS CF Polls Received Count                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   QoS CF Polls Unused Count                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  QoS CF Polls Unusable Count                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1039 for IEEE 802.11 Statistics

Length:   80

********************************************************************/

/* */
static void capwap_80211_statistics_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_statistics_element* element = (struct capwap_80211_statistics_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u8(handle, element->radioid);
	func->write_block(handle, NULL, 3);
	func->write_u32(handle, element->txfragment);
	func->write_u32(handle, element->multicasttx);
	func->write_u32(handle, element->failed);
	func->write_u32(handle, element->retry);
	func->write_u32(handle, element->multipleretry);
	func->write_u32(handle, element->frameduplicate);
	func->write_u32(handle, element->rtssuccess);
	func->write_u32(handle, element->rtsfailure);
	func->write_u32(handle, element->ackfailure);
	func->write_u32(handle, element->rxfragment);
	func->write_u32(handle, element->multicastrx);
	func->write_u32(handle, element->fcserror);
	func->write_u32(handle, element->txframe);
	func->write_u32(handle, element->decryptionerror);
	func->write_u32(handle, element->discardedqosfragment);
	func->write_u32(handle, element->associatedstation);
	func->write_u32(handle, element->qoscfpollsreceived);
	func->write_u32(handle, element->qoscfpollsunused);
	func->write_u32(handle, element->qoscfpollsunusable);
}

/* */
static void* capwap_80211_statistics_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_statistics_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 80) {
		capwap_logging_debug("Invalid IEEE 802.11 Statistics element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_statistics_element*)capwap_alloc(sizeof(struct capwap_80211_statistics_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_80211_statistics_element));
	func->read_u8(handle, &data->radioid);
	func->read_block(handle, NULL, 3);
	func->read_u32(handle, &data->txfragment);
	func->read_u32(handle, &data->multicasttx);
	func->read_u32(handle, &data->failed);
	func->read_u32(handle, &data->retry);
	func->read_u32(handle, &data->multipleretry);
	func->read_u32(handle, &data->frameduplicate);
	func->read_u32(handle, &data->rtssuccess);
	func->read_u32(handle, &data->rtsfailure);
	func->read_u32(handle, &data->ackfailure);
	func->read_u32(handle, &data->rxfragment);
	func->read_u32(handle, &data->multicastrx);
	func->read_u32(handle, &data->fcserror);
	func->read_u32(handle, &data->txframe);
	func->read_u32(handle, &data->decryptionerror);
	func->read_u32(handle, &data->discardedqosfragment);
	func->read_u32(handle, &data->associatedstation);
	func->read_u32(handle, &data->qoscfpollsreceived);
	func->read_u32(handle, &data->qoscfpollsunused);
	func->read_u32(handle, &data->qoscfpollsunusable);

	return data;
}

/* */
static void capwap_80211_statistics_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_statistics_ops = {
	.create_message_element = capwap_80211_statistics_element_create,
	.parsing_message_element = capwap_80211_statistics_element_parsing,
	.free_parsed_message_element = capwap_80211_statistics_element_free
};
