#include "capwap.h"

/* Helper exit */
void capwap_exit(int errorcode) {
	exit(errorcode);
}

/* Helper timeout calc */
void capwap_init_timeout(struct timeout_control* timeout) {
	ASSERT(timeout);

	memset(timeout, 0, sizeof(struct timeout_control));
}

void capwap_update_timeout(struct timeout_control* timeout) {
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

long capwap_get_timeout(struct timeout_control* timeout, long* index) {
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

void capwap_wait_timeout(struct timeout_control* timeout, unsigned long index) {
	ASSERT(timeout != NULL);
	ASSERT(index < CAPWAP_MAX_TIMER);

	if (timeout->items[index].enable) {
		for (capwap_update_timeout(timeout); timeout->items[index].delta > 0; capwap_update_timeout(timeout)) {
			usleep((useconds_t)timeout->items[index].delta * 1000);
		}
	}
}

int capwap_is_enable_timeout(struct timeout_control* timeout, unsigned long index) {
	ASSERT(timeout != NULL);
	ASSERT(index < CAPWAP_MAX_TIMER);

	return (timeout->items[index].enable ? 1 : 0);
}

int capwap_is_timeout(struct timeout_control* timeout, unsigned long index) {
	ASSERT(timeout != NULL);
	ASSERT(index < CAPWAP_MAX_TIMER);

	if (timeout->items[index].enable && (timeout->items[index].delta <= 0)) {
		return 1;
	}

	return 0;
}

void capwap_set_timeout(unsigned long value, struct timeout_control* timeout, unsigned long index) {
	ASSERT(timeout != NULL);
	ASSERT(index < CAPWAP_MAX_TIMER);
	
	/* Set timeout in ms */
	timeout->items[index].enable = 1;
	timeout->items[index].delta = value * 1000;
	timeout->items[index].durate = value * 1000;
	gettimeofday(&timeout->items[index].timestop, NULL);
	timeout->items[index].timestop.tv_sec += value;
}

void capwap_kill_timeout(struct timeout_control* timeout, unsigned long index) {
	ASSERT(timeout != NULL);
	ASSERT(index < CAPWAP_MAX_TIMER);
	
	timeout->items[index].enable = 0;
}

void capwap_killall_timeout(struct timeout_control* timeout) {
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

	clone = capwap_alloc(sizeof(char) * (strlen(source) + 1));
	if (!clone) {
		capwap_outofmemory();
	}

	strcpy(clone, source);
	return clone;
}

/* Buffer clone */
void* capwap_clone(void* buffer, int buffersize) {
	void* bufferclone;
	
	ASSERT(buffer != NULL);
	ASSERT(buffersize > 0);

	bufferclone = capwap_alloc(buffersize);
	if (!bufferclone) {
		capwap_outofmemory();
	}

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
