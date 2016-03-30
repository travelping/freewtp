#include "capwap.h"
#include "capwap_lock.h"
#include "capwap_logging.h"

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

#ifdef DEBUG
/* */
void capwap_lock_destroy_debug(capwap_lock_t* lock, const char* file, const int line) {
	int res;

	ASSERT(lock != NULL);

	res = pthread_mutex_trylock(&lock->mutex);
	if (!res) {
		pthread_mutex_unlock(&lock->mutex);
	} else if (res == EINVAL) {
		log_printf(LOG_DEBUG, "Attempt to destroy invalid mutex from '%s' (%d)", file, line);
		capwap_backtrace_callstack();
	} else if (res == EBUSY) {
		log_printf(LOG_DEBUG, "Attempt to destroy locked mutex by '%s' (%d) from '%s' (%d)", lock->file, lock->line, file, line);
		capwap_backtrace_callstack();
	}

	pthread_mutex_destroy(&lock->mutex);
}

/* */
void capwap_lock_enter_debug(capwap_lock_t* lock, const char* file, const int line) {
	int res;
	time_t starttime;
	time_t waittime;
	time_t lasttime = 0;

	ASSERT(lock != NULL);

	/* */
	starttime = time(NULL);

	do {
		res = pthread_mutex_trylock(&lock->mutex);
		if (res == EBUSY) {
			waittime = time(NULL) - starttime;
			if (!(waittime % 5) && (waittime > lasttime)) {
				lasttime = waittime;
				log_printf(LOG_DEBUG, "Waited %d sec for mutex '%s' (%d) locked by '%s' (%d)", waittime, file, line, lock->file, lock->line);
				capwap_backtrace_callstack();
			}

			usleep(200);
		}
	} while (res == EBUSY);

	/* */
	lock->file = (char*)file;
	lock->line = (int)line;
}

/* */
void capwap_lock_exit_debug(capwap_lock_t* lock, const char* file, const int line) {
	ASSERT(lock != NULL);

	/* */
	lock->file = NULL;
	lock->line = 0;

	/* */
	if (pthread_mutex_unlock(&lock->mutex)) {
		log_printf(LOG_DEBUG, "Error releasing mutex '%s' (%d)", file, line);
		capwap_backtrace_callstack();
	}
}
#else
/* */
void capwap_lock_destroy(capwap_lock_t* lock) {
	pthread_mutex_destroy(&lock->mutex);
}

/* */
void capwap_lock_enter(capwap_lock_t* lock) {
	pthread_mutex_lock(&lock->mutex);
}

/* */
void capwap_lock_exit(capwap_lock_t* lock) {
	pthread_mutex_unlock(&lock->mutex);
}
#endif
