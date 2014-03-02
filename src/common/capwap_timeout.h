#ifndef __CAPWAP_TIMEOUT_HEADER__
#define __CAPWAP_TIMEOUT_HEADER__

#include "capwap_hash.h"
#include "capwap_list.h"

/* */
#define CAPWAP_TIMEOUT_BITFIELD_SIZE			128
#define CAPWAP_TIMEOUT_INFINITE					-1
#define CAPWAP_TIMEOUT_INDEX_NO_SET				0

/* */
struct capwap_timeout {
	uint32_t timeoutbitfield[CAPWAP_TIMEOUT_BITFIELD_SIZE];
	struct capwap_hash* itemsreference;
	struct capwap_list* itemstimeout;
};

/* */
typedef void (*capwap_timeout_expire)(struct capwap_timeout* timeout, unsigned long index, void* context, void* param);

struct capwap_timeout_item {
	unsigned long index;
	long durate;
	struct timeval expire;
	capwap_timeout_expire callback;
	void* context;
	void* param;
};

/* */
struct capwap_timeout* capwap_timeout_init(void);
void capwap_timeout_free(struct capwap_timeout* timeout);

/* */
unsigned long capwap_timeout_createtimer(struct capwap_timeout* timeout);
void capwap_timeout_deletetimer(struct capwap_timeout* timeout, unsigned long index);

/* */
unsigned long capwap_timeout_set(struct capwap_timeout* timeout, unsigned long index, long durate, capwap_timeout_expire callback, void* context, void* param);
void capwap_timeout_unset(struct capwap_timeout* timeout, unsigned long index);
void capwap_timeout_unsetall(struct capwap_timeout* timeout);

long capwap_timeout_getcoming(struct capwap_timeout* timeout);
unsigned long capwap_timeout_hasexpired(struct capwap_timeout* timeout);

int capwap_timeout_wait(long durate);

#endif /* __CAPWAP_TIMEOUT_HEADER__ */
