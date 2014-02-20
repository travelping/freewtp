#ifndef __CAPWAP_TIMEOUT_HEADER__
#define __CAPWAP_TIMEOUT_HEADER__

#define CAPWAP_TIMER_UNDEF						-1
#define CAPWAP_TIMER_CONTROL_CONNECTION			0
#define CAPWAP_TIMER_CONTROL_ECHO				1
#define CAPWAP_TIMER_DATA_KEEPALIVE				2
#define CAPWAP_TIMER_DATA_KEEPALIVEDEAD			3
#define CAPWAP_MAX_TIMER						4

/* */
struct timeout_control_item {
	int enable;
	long delta;
	unsigned long durate;
	struct timeval timestop;
};

struct timeout_control {
	struct timeout_control_item items[CAPWAP_MAX_TIMER];
};

/* */
struct timeout_control* capwap_timeout_init(void);
void capwap_timeout_free(struct timeout_control* timeout);

long capwap_timeout_get(struct timeout_control* timeout, long* index);
void capwap_timeout_update(struct timeout_control* timeout);
void capwap_timeout_set(unsigned long value, struct timeout_control* timeout, unsigned long index);

void capwap_timeout_wait(struct timeout_control* timeout, unsigned long index);

int capwap_timeout_isenable(struct timeout_control* timeout, unsigned long index);
int capwap_timeout_hasexpired(struct timeout_control* timeout, unsigned long index);

void capwap_timeout_kill(struct timeout_control* timeout, unsigned long index);
void capwap_timeout_killall(struct timeout_control* timeout);

#endif /* __CAPWAP_TIMEOUT_HEADER__ */
