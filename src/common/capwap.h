#ifndef __CAPWAP_HEADER__
#define __CAPWAP_HEADER__

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <net/if.h>

//TODO:
//#ifdef NATIVE_UDPLITE_HEADER
//#include <netinet/udplite.h>
//#else
//#define IPPROTO_UDPLITE       136
#define SOL_UDPLITE           136
#define UDPLITE_SEND_CSCOV     10
//#endif

/* Endian */
#ifdef WIN32
	#define CAPWAP_LITTLE_ENDIAN
#else
	#if __BYTE_ORDER == __BIG_ENDIAN
		#define CAPWAP_BIG_ENDIAN
	#else
		#define CAPWAP_LITTLE_ENDIAN
	#endif
#endif

/* Min & Max */
#ifndef max
	#define max(a,b) ((a) >= (b) ? (a) : (b))
#endif

#ifndef min
	#define min(a,b) ((a) <= (b) ? (a) : (b))
#endif

/* config */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* standard include */
#include "capwap_logging.h"
#include "capwap_debug.h"
#include "capwap_error.h"

/* Helper exit */
void capwap_exit(int errorcode);

/* Random generator */
void capwap_init_rand(void);
int capwap_get_rand(int max);

/* Helper timeout calc */
struct timeout_control_item {
	int enable;
	long delta;
	unsigned long durate;
	struct timeval timestop;
};

#define CAPWAP_TIMER_UNDEF						-1
#define CAPWAP_TIMER_CONTROL_CONNECTION			0
#define CAPWAP_TIMER_CONTROL_ECHO				1
#define CAPWAP_TIMER_DATA_KEEPALIVE				2
#define CAPWAP_TIMER_DATA_KEEPALIVEDEAD			3
#define CAPWAP_MAX_TIMER						4

struct timeout_control {
	struct timeout_control_item items[CAPWAP_MAX_TIMER];
};

void capwap_init_timeout(struct timeout_control* timeout);
long capwap_get_timeout(struct timeout_control* timeout, long* index);
void capwap_update_timeout(struct timeout_control* timeout);
void capwap_set_timeout(unsigned long value, struct timeout_control* timeout, unsigned long index);
void capwap_kill_timeout(struct timeout_control* timeout, unsigned long index);
void capwap_killall_timeout(struct timeout_control* timeout);
int capwap_is_enable_timeout(struct timeout_control* timeout, unsigned long index);
int capwap_is_timeout(struct timeout_control* timeout, unsigned long index);

/* */
#define capwap_outofmemory()						capwap_logging_fatal("Out of memory %s(%d)", __FILE__, __LINE__);	\
													capwap_exit(CAPWAP_OUT_OF_MEMORY);

/* Helper buffer copy */
char* capwap_duplicate_string(const char* source);
void* capwap_clone(void* buffer, int buffersize);

#endif /* __CAPWAP_HEADER__ */
