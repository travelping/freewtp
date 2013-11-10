#ifndef __CAPWAP_LOCK_HEADER__
#define __CAPWAP_LOCK_HEADER__

#ifdef CAPWAP_MULTITHREADING_ENABLE

#include <pthread.h>

typedef struct {
	pthread_mutex_t mutex;
#ifdef DEBUG
	char* file;
	int line;
#endif
} capwap_lock_t;

int capwap_lock_init(capwap_lock_t* lock);

#ifdef DEBUG
#define capwap_lock_destroy(lock)						capwap_lock_destroy_debug(lock, __FILE__, __LINE__)
void capwap_lock_destroy_debug(capwap_lock_t* lock, const char* file, const int line);

#define capwap_lock_enter(lock)							capwap_lock_enter_debug(lock, __FILE__, __LINE__)
void capwap_lock_enter_debug(capwap_lock_t* lock, const char* file, const int line);

#define capwap_lock_exit(lock)							capwap_lock_exit_debug(lock, __FILE__, __LINE__)
void capwap_lock_exit_debug(capwap_lock_t* lock, const char* file, const int line);
#else
void capwap_lock_destroy(capwap_lock_t* lock);
void capwap_lock_enter(capwap_lock_t* lock);
void capwap_lock_exit(capwap_lock_t* lock);
#endif

#endif /* CAPWAP_MULTITHREADING_ENABLE */

#endif /* __CAPWAP_LOCK_HEADER__ */
