#include "capwap.h"
#include "capwap_lock.h"

#ifndef CAPWAP_MULTITHREADING_ENABLE
#error "Warning: multithreading is disabled\n"
#endif

/* */
int capwap_lock_init(capwap_lock_t* lock) {
	ASSERT(lock != NULL);

	memset(lock, 0, sizeof(capwap_lock_t));
	if (pthread_mutex_init(&lock->mutex, NULL) != 0) {
		return 0;
	}

	return 1;
}

/* */
void capwap_lock_destroy(capwap_lock_t* lock) {
	ASSERT(lock != NULL);
	
	pthread_mutex_destroy(&lock->mutex);
}

/* */
void capwap_lock_enter(capwap_lock_t* lock) {
	ASSERT(lock != NULL);
	
	pthread_mutex_lock(&lock->mutex);
}

/* */
void capwap_lock_exit(capwap_lock_t* lock) {
	ASSERT(lock != NULL);
	
	pthread_mutex_unlock(&lock->mutex);
}
