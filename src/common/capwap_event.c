#include "capwap.h"
#include "capwap_event.h"

#ifndef CAPWAP_MULTITHREADING_ENABLE
#error "Warning: multithreading is disabled\n"
#endif

/* */
int capwap_event_init(capwap_event_t* e) {
	ASSERT(e != NULL);

	e->set = 0;
	
    if (pthread_cond_init(&e->event, NULL) != 0) {
    	return 0;
    }
    	
    if (pthread_mutex_init(&e->mutex, NULL) != 0) {
    	pthread_cond_destroy(&e->event);
    	return 0;
    }
    	
    return 1;
}

/* */
void capwap_event_destroy(capwap_event_t* e) {
	ASSERT(e != NULL);
	
	pthread_cond_destroy(&e->event);
	pthread_mutex_destroy(&e->mutex);
}

/* */
void capwap_event_signal(capwap_event_t* e) {
	ASSERT(e != NULL);

	pthread_mutex_lock(&e->mutex);
	
	e->set = 1;
	pthread_cond_signal(&e->event);
	
	pthread_mutex_unlock(&e->mutex);
}

/* */
void capwap_event_reset(capwap_event_t* e) {
	ASSERT(e != NULL);

	pthread_mutex_lock(&e->mutex);
	
	e->set = 0;

	pthread_mutex_unlock(&e->mutex);
}

/* */
void capwap_event_wait(capwap_event_t* e) {
	capwap_event_wait_timeout(e, -1);
}

/* */
int capwap_event_wait_timeout(capwap_event_t* e, long timeout) {
	int result = 0;
	
	ASSERT(e != NULL);
	
	pthread_mutex_lock(&e->mutex);
	
	if (e->set) {
		result = 1;
	} else if (timeout < 0) {
		if (!pthread_cond_wait(&e->event, &e->mutex)) {
			result = 1;
		}
	} else {
		struct timeval tp;
			
		gettimeofday(&tp, NULL);
		tp.tv_sec += timeout / 1000;
		tp.tv_usec += ((timeout % 1000) * 1000);
		if (tp.tv_usec > 1000000) {
			tp.tv_sec++;
			tp.tv_usec -= 1000000;
		}

		struct timespec ts;
		ts.tv_sec  = tp.tv_sec;
		ts.tv_nsec = tp.tv_usec * 1000;
		if (!pthread_cond_timedwait(&e->event, &e->mutex, &ts)) {
			result = 1;
		}
	}
	
	e->set = 0;
	pthread_mutex_unlock(&e->mutex);
	
	return result;
}
