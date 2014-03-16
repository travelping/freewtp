#include "capwap.h"

/* */
#define CAPWAP_TIMEOUT_HASH_COUNT				128

/* */
static unsigned long capwap_timeout_hash_item_gethash(const void* key, unsigned long keysize, unsigned long hashsize) {
	return (*(unsigned long*)key % hashsize);
}

/* */
static int capwap_timeout_hash_item_cmp(const void* key1, const void* key2, unsigned long keysize) {
	unsigned long value1 = *(unsigned long*)key1;
	unsigned long value2 = *(unsigned long*)key2;

	return ((value1 == value2) ? 0 : ((value1 < value2) ? -1 : 1));
}

/* */
static long capwap_timeout_getdelta(struct timeval* time1, struct timeval* time2) {
	return (time1->tv_sec - time2->tv_sec) * 1000 + (time1->tv_usec - time2->tv_usec) / 1000;
}

/* */
static unsigned long capwap_timeout_set_bitfield(struct capwap_timeout* timeout) {
	int i, j;

	ASSERT(timeout != NULL);

	/* Search free bitfield */
	for (i = 0; i < CAPWAP_TIMEOUT_BITFIELD_SIZE; i++) {
		if (timeout->timeoutbitfield[i] != 0xffffffff) {
			uint32_t bitfield = timeout->timeoutbitfield[i];

			for (j = 0; j < 32; j++) {
				if (!(bitfield & (1 << j))) {
					timeout->timeoutbitfield[i] |= (1 << j);
					return (i * 32 + j + 1);
				}
			}
		}
	}

	return CAPWAP_TIMEOUT_INDEX_NO_SET;
}

/* */
static void capwap_timeout_clear_bitfield(struct capwap_timeout* timeout, unsigned long value) {
	ASSERT(timeout != NULL);
	ASSERT(value > 0);

	timeout->timeoutbitfield[(value - 1) / 32] &= ~(1 << ((value - 1) % 32));
}

/* */
static void capwap_timeout_additem(struct capwap_list* itemstimeout, struct capwap_list_item* itemlist) {
	struct capwap_list_item* search;
	struct capwap_list_item* last = NULL;
	struct capwap_timeout_item* item = (struct capwap_timeout_item*)itemlist->item;

	/* */
	search = itemstimeout->first;
	while (search) {
		struct capwap_timeout_item* itemsearch = (struct capwap_timeout_item*)search->item;

		if (capwap_timeout_getdelta(&item->expire, &itemsearch->expire) < 0) {
			capwap_itemlist_insert_before(itemstimeout, last, itemlist);
			break;
		}

		/* Next */
		last = search;
		search = search->next;
	}

	/* */
	if (!search) {
		capwap_itemlist_insert_after(itemstimeout, NULL, itemlist);
	}
}

/* */
static void capwap_timeout_setexpire(long durate, struct timeval* now, struct timeval* expire) {
	expire->tv_sec = now->tv_sec + durate / 1000;
	expire->tv_usec = now->tv_usec + durate % 1000;
	if (expire->tv_usec >= 1000000) {
		expire->tv_sec++;
		expire->tv_usec -= 1000000;
	}
}

/* */
struct capwap_timeout* capwap_timeout_init(void) {
	struct capwap_timeout* timeout;

	/* */
	timeout = (struct capwap_timeout*)capwap_alloc(sizeof(struct capwap_timeout));
	memset(timeout, 0, sizeof(struct capwap_timeout));

	/* */
	timeout->itemsreference = capwap_hash_create(CAPWAP_TIMEOUT_HASH_COUNT, sizeof(unsigned long), capwap_timeout_hash_item_gethash, capwap_timeout_hash_item_cmp, NULL);
	timeout->itemstimeout = capwap_list_create();

	return timeout;
}

/* */
void capwap_timeout_free(struct capwap_timeout* timeout) {
	ASSERT(timeout != NULL);

	capwap_hash_free(timeout->itemsreference);
	capwap_list_free(timeout->itemstimeout);
	capwap_free(timeout);
}

/* */
unsigned long capwap_timeout_createtimer(struct capwap_timeout* timeout) {
	unsigned long index;

	ASSERT(timeout != NULL);

	/* Create new timeout index */
	index = capwap_timeout_set_bitfield(timeout);
	capwap_logging_debug("Create new timer: %lu", index);

	return index;
}

/* */
void capwap_timeout_deletetimer(struct capwap_timeout* timeout, unsigned long index) {
	ASSERT(timeout != NULL);

	if (index != CAPWAP_TIMEOUT_INDEX_NO_SET) {
		capwap_logging_debug("Delete timer: %lu", index);

		/* Unset timeout timer */
		capwap_timeout_unset(timeout, index);

		/* Release timer index */
		capwap_timeout_clear_bitfield(timeout, index);
	}
}

/* */
unsigned long capwap_timeout_set(struct capwap_timeout* timeout, unsigned long index, long durate, capwap_timeout_expire callback, void* context, void* param) {
	struct capwap_list_item* itemlist;
	struct capwap_timeout_item* item;
	struct timeval now;

	ASSERT(timeout != NULL);
	ASSERT(durate >= 0);

	gettimeofday(&now, NULL);

	if (index == CAPWAP_TIMEOUT_INDEX_NO_SET) {
		index = capwap_timeout_createtimer(timeout);
	} else {
		/* Check can update timeout timer */
		itemlist = (struct capwap_list_item*)capwap_hash_search(timeout->itemsreference, &index);
		if (itemlist) {
			/* Remove from timeout list */
			capwap_itemlist_remove(timeout->itemstimeout, itemlist);

			/* Update timeout */
			item = (struct capwap_timeout_item*)itemlist->item;
			item->durate = durate;
			capwap_timeout_setexpire(item->durate, &now, &item->expire);
			item->callback = callback;
			item->context = context;
			item->param = param;

			capwap_logging_debug("Update timeout: %lu %ld", item->index, item->durate);

			/* Add itemlist into order list */
			capwap_timeout_additem(timeout->itemstimeout, itemlist);
			return index;
		}
	}

	/* Create new timeout timer */
	itemlist = capwap_itemlist_create(sizeof(struct capwap_timeout_item));
	item = (struct capwap_timeout_item*)itemlist->item;

	/* */
	item->index = index;
	item->durate = durate;
	capwap_timeout_setexpire(item->durate, &now, &item->expire);
	item->callback = callback;
	item->context = context;
	item->param = param;

	capwap_logging_debug("Set timeout: %lu %ld", item->index, item->durate);

	/* Add itemlist into hash for rapid searching */
	capwap_hash_add(timeout->itemsreference, (const void*)&item->index, (void*)itemlist);

	/* Add itemlist into order list */
	capwap_timeout_additem(timeout->itemstimeout, itemlist);

	return item->index;
}

/* */
void capwap_timeout_unset(struct capwap_timeout* timeout, unsigned long index) {
	struct capwap_list_item* itemlist;

	ASSERT(timeout != NULL);

	if (index != CAPWAP_TIMEOUT_INDEX_NO_SET) {
		itemlist = (struct capwap_list_item*)capwap_hash_search(timeout->itemsreference, &index);
		if (itemlist) {
			capwap_logging_debug("Unset timeout: %lu", index);
			capwap_hash_delete(timeout->itemsreference, &index);
			capwap_itemlist_free(capwap_itemlist_remove(timeout->itemstimeout, itemlist));
		}
	}
}

/* */
void capwap_timeout_unsetall(struct capwap_timeout* timeout) {
	capwap_hash_deleteall(timeout->itemsreference);
	capwap_list_flush(timeout->itemstimeout);
}

/* */
long capwap_timeout_getcoming(struct capwap_timeout* timeout) {
	long delta;
	struct timeval now;
	struct capwap_list_item* search;
	struct capwap_timeout_item* item;

	ASSERT(timeout != NULL);

	/* */
	search = timeout->itemstimeout->first;
	if (!search) {
		return CAPWAP_TIMEOUT_INFINITE;
	}

	/* */
	gettimeofday(&now, NULL);
	item = (struct capwap_timeout_item*)search->item;
	delta = capwap_timeout_getdelta(&item->expire, &now);

	if (delta <= 0) {
		return 0;
	} else if (delta <= item->durate) {
		return delta;
	}

	/* Recalculate all timeouts because delta > item->durate */
	while (search) {
		struct capwap_timeout_item* itemsearch = (struct capwap_timeout_item*)search->item;

		capwap_timeout_setexpire(itemsearch->durate, &now, &itemsearch->expire);
		search = search->next;
	}

	return item->durate;
}

/* */
unsigned long capwap_timeout_hasexpired(struct capwap_timeout* timeout) {
	long delta;
	struct capwap_timeout_item* item;
	struct capwap_list_item* itemlist;
	unsigned long index;
	capwap_timeout_expire callback;
	void* context;
	void* param;

	ASSERT(timeout != NULL);

	/* */
	delta = capwap_timeout_getcoming(timeout);
	if ((delta > 0) || (delta == CAPWAP_TIMEOUT_INFINITE))  {
		return 0;
	}

	/* */
	itemlist = capwap_itemlist_remove_head(timeout->itemstimeout);
	item = (struct capwap_timeout_item*)itemlist->item;

	capwap_logging_debug("Expired timeout: %lu", item->index);

	/* Cache callback before release timeout timer */
	index = item->index;
	callback = item->callback;
	context = item->context;
	param = item->param;

	/* Free memory */
	capwap_hash_delete(timeout->itemsreference, &index);
	capwap_itemlist_free(itemlist);

	/* */
	if (callback) {
		callback(timeout, index, context, param);
	}

	return index;
}

/* */
int capwap_timeout_wait(long durate) {
	if (durate < 0) {
		return -1;
	} else if (durate > 0) {
		if (usleep((useconds_t)durate * 1000)) {
			return ((errno == EINTR) ? 0 : -1);
		}
	}

	return 1;
}
