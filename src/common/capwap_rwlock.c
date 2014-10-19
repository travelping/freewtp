#include "capwap.h"
#include "capwap_rwlock.h"

#ifndef CAPWAP_MULTITHREADING_ENABLE
#error "Warning: multithreading is disabled\n"
#endif

/* */
int capwap_rwlock_init(capwap_rwlock_t* lock) {
	ASSERT(lock != NULL);

	if (pthread_rwlock_init(&lock->rwlock, NULL)) {
		return 0;
	}

	return 1;
}

/* */
void capwap_rwlock_destroy(capwap_rwlock_t* lock) {
	ASSERT(lock != NULL);

	pthread_rwlock_destroy(&lock->rwlock);
}

/* */
void capwap_rwlock_rdlock(capwap_rwlock_t* lock) {
	ASSERT(lock != NULL);

	pthread_rwlock_rdlock(&lock->rwlock);
}

/* */
void capwap_rwlock_wrlock(capwap_rwlock_t* lock) {
	ASSERT(lock != NULL);

	pthread_rwlock_wrlock(&lock->rwlock);
}

/* */
void capwap_rwlock_unlock(capwap_rwlock_t* lock) {
	ASSERT(lock != NULL);

	pthread_rwlock_unlock(&lock->rwlock);
}
