#include "capwap.h"

/* Helper exit */
void capwap_exit(int errorcode) {
	exit(errorcode);
}

/* Helper timeout calc */
struct timeout_control* capwap_timeout_init(void) {
	struct timeout_control* timeout;

	timeout = (struct timeout_control*)capwap_alloc(sizeof(struct timeout_control));
	memset(timeout, 0, sizeof(struct timeout_control));

	return timeout;
}

/* */
void capwap_timeout_free(struct timeout_control* timeout) {
	ASSERT(timeout != NULL);

	capwap_free(timeout);
}

/* */
void capwap_timeout_update(struct timeout_control* timeout) {
	int i;
	struct timeval now;
	
	ASSERT(timeout);
	
	gettimeofday(&now, NULL);
	
	for (i = 0; i < CAPWAP_MAX_TIMER; i++) {
		if (timeout->items[i].enable && (timeout->items[i].delta >= 0)) {
			timeout->items[i].delta = (timeout->items[i].timestop.tv_sec - now.tv_sec) * 1000 + (timeout->items[i].timestop.tv_usec - now.tv_usec) / 1000;
			if (timeout->items[i].delta < 0) {
				timeout->items[i].delta = 0;
			} else if (timeout->items[i].delta > timeout->items[i].durate) {
				/* Changed system time */
				timeout->items[i].delta = timeout->items[i].durate;
				memcpy(&timeout->items[i].timestop, &now, sizeof(struct timeval));
				timeout->items[i].timestop.tv_sec += timeout->items[i].durate;
			}
		}
	}
}

/* */
long capwap_timeout_get(struct timeout_control* timeout, long* index) {
	long i;
	long delta = 0;

	ASSERT(timeout != NULL);
	ASSERT(index != NULL);
	
	*index = CAPWAP_TIMER_UNDEF;
	for (i = 0; i < CAPWAP_MAX_TIMER; i++) {
		if (timeout->items[i].enable) {
			if (timeout->items[i].delta <= 0) {
				*index = i;
				delta = 0;
				break;
			} else if (!delta || (delta > timeout->items[i].delta)) {
				*index = i;
				delta = timeout->items[i].delta;
			}
		}
	}
	
	return delta;
}

/* */
void capwap_timeout_wait(struct timeout_control* timeout, unsigned long index) {
	ASSERT(timeout != NULL);
	ASSERT(index < CAPWAP_MAX_TIMER);

	if (timeout->items[index].enable) {
		for (capwap_timeout_update(timeout); timeout->items[index].delta > 0; capwap_timeout_update(timeout)) {
			usleep((useconds_t)timeout->items[index].delta * 1000);
		}
	}
}

/* */
int capwap_timeout_isenable(struct timeout_control* timeout, unsigned long index) {
	ASSERT(timeout != NULL);
	ASSERT(index < CAPWAP_MAX_TIMER);

	return (timeout->items[index].enable ? 1 : 0);
}

/* */
int capwap_timeout_hasexpired(struct timeout_control* timeout, unsigned long index) {
	ASSERT(timeout != NULL);
	ASSERT(index < CAPWAP_MAX_TIMER);

	if (timeout->items[index].enable && (timeout->items[index].delta <= 0)) {
		return 1;
	}

	return 0;
}

/* */
void capwap_timeout_set(unsigned long value, struct timeout_control* timeout, unsigned long index) {
	ASSERT(timeout != NULL);
	ASSERT(index < CAPWAP_MAX_TIMER);
	
	/* Set timeout in ms */
	timeout->items[index].enable = 1;
	timeout->items[index].delta = value * 1000;
	timeout->items[index].durate = timeout->items[index].delta;
	gettimeofday(&timeout->items[index].timestop, NULL);
	timeout->items[index].timestop.tv_sec += value;
}

/* */
void capwap_timeout_kill(struct timeout_control* timeout, unsigned long index) {
	ASSERT(timeout != NULL);
	ASSERT(index < CAPWAP_MAX_TIMER);
	
	timeout->items[index].enable = 0;
}

/* */
void capwap_timeout_killall(struct timeout_control* timeout) {
	long i;

	ASSERT(timeout != NULL);

	for (i = 0; i < CAPWAP_MAX_TIMER; i++) {
		timeout->items[i].enable = 0;
	}
}

/* Init randon generator */
void capwap_init_rand(void) {
	srand(time(NULL));
}

/* Get random number */
int capwap_get_rand(int max) {
	if ((max < 0) || (max > RAND_MAX)) {
		max = RAND_MAX;
	}

	return (rand() % max);
}

/* Duplicate string */
char* capwap_duplicate_string(const char* source) {
	char* clone;

	ASSERT(source != NULL);

	clone = capwap_alloc(strlen(source) + 1);
	strcpy(clone, source);

	return clone;
}

/* Buffer clone */
void* capwap_clone(const void* buffer, int buffersize) {
	void* bufferclone;
	
	ASSERT(buffer != NULL);
	ASSERT(buffersize > 0);

	bufferclone = capwap_alloc(buffersize);
	return memcpy(bufferclone, buffer, buffersize);
}

/* */
void capwap_daemon(void) {
	int fd;
	pid_t pid;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		capwap_exit(CAPWAP_DAEMON_ERROR);
	} else if (pid > 0) {
		capwap_exit(CAPWAP_SUCCESSFUL);
	}

	/* Change the file mode mask */
	umask(0);

	/* Create a new SID for the child process */
	if (setsid() < 0) {
		capwap_exit(CAPWAP_DAEMON_ERROR);
	}

	/* Change the current working directory */
	if ((chdir("/")) < 0) {
		capwap_exit(CAPWAP_DAEMON_ERROR);
	}

	/* Redirect the standard file descriptors to /dev/null */
	fd = open("/dev/null", 0);
	if (fd == -1) {
		capwap_exit(CAPWAP_DAEMON_ERROR);
	}

	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	close(fd);
}

/* */
char* capwap_itoa(int input, char* output) {
	sprintf(output, "%d", input);
	return output;
}

/* */
char* capwap_ltoa(long input, char* output) {
	sprintf(output, "%ld", input);
	return output;
}
