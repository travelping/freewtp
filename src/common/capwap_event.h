#ifndef __CAPWAP_EVENT_HEADER__
#define __CAPWAP_EVENT_HEADER__

#ifdef CAPWAP_MULTITHREADING_ENABLE

#include <pthread.h>

typedef struct {
	char set;
	pthread_cond_t event;
	pthread_mutex_t mutex;
} capwap_event_t;

int capwap_event_init(capwap_event_t* e);
void capwap_event_destroy(capwap_event_t* e);
void capwap_event_signal(capwap_event_t* e);
void capwap_event_reset(capwap_event_t* e);
void capwap_event_wait(capwap_event_t* e);
int capwap_event_wait_timeout(capwap_event_t* e, long timeout);

#endif /* CAPWAP_MULTITHREADING_ENABLE */

#endif /* __CAPWAP_EVENT_HEADER__ */
