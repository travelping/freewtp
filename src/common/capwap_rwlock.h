#ifndef __CAPWAP_RWLOCK_HEADER__
#define __CAPWAP_RWLOCK_HEADER__

#ifdef CAPWAP_MULTITHREADING_ENABLE

#include <pthread.h>

typedef struct {
	pthread_rwlock_t rwlock;
} capwap_rwlock_t;

int capwap_rwlock_init(capwap_rwlock_t* lock);
void capwap_rwlock_destroy(capwap_rwlock_t* lock);
void capwap_rwlock_rdlock(capwap_rwlock_t* lock);
void capwap_rwlock_wrlock(capwap_rwlock_t* lock);
void capwap_rwlock_unlock(capwap_rwlock_t* lock);

#endif /* CAPWAP_MULTITHREADING_ENABLE */

#endif /* __CAPWAP_RWLOCK_HEADER__ */
