#ifndef __CAPWAP_LOCK_HEADER__
#define __CAPWAP_LOCK_HEADER__

#ifdef CAPWAP_MULTITHREADING_ENABLE

#include <pthread.h>

typedef struct {
	pthread_mutex_t mutex;
} capwap_lock_t;

int capwap_lock_init(capwap_lock_t* lock);
void capwap_lock_destroy(capwap_lock_t* lock);
void capwap_lock_enter(capwap_lock_t* lock);
void capwap_lock_exit(capwap_lock_t* lock);

#endif /* CAPWAP_MULTITHREADING_ENABLE */

#endif /* __CAPWAP_LOCK_HEADER__ */
