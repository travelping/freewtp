#include "capwap.h"

/* Helper exit */
void capwap_exit(int errorcode) {
	exit(errorcode);
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
