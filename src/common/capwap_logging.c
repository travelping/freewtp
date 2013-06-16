#include "capwap.h"
#include "capwap_logging.h"

#ifdef CAPWAP_MULTITHREADING_ENABLE 
#include "capwap_lock.h"

static capwap_lock_t l_loglock;
#endif

/* */
static int logginglevel = CAPWAP_LOGGING_NONE;
static int loggingoutputstdout = 0;
static int loggingoutputstderr = 0;

/* */
static char logginglevelid[] = { 'N', 'F', 'E', 'W', 'I', 'D' };

/* */
static void prefix_logging(int level, char* buffer) {
	time_t timenow;
	struct tm* tmnow;
	
	time(&timenow);
	tmnow = localtime(&timenow);
	sprintf(buffer, "[%02d/%02d/%04d %02d:%02d:%02d] <%c> ", tmnow->tm_mday, tmnow->tm_mon + 1, tmnow->tm_year + 1900, tmnow->tm_hour, tmnow->tm_min, tmnow->tm_sec, logginglevelid[level]);
}

/* */
void capwap_logging_init() {
#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_init(&l_loglock);
#endif
}

/* */
void capwap_logging_close() {
#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_destroy(&l_loglock);
#endif
}

/* */
void capwap_logging_verboselevel(unsigned int level) {
#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_enter(&l_loglock);
#endif

	logginglevel = level;

#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_exit(&l_loglock);
#endif
}

/* */
void capwap_logging_disable_allinterface() {
#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_enter(&l_loglock);
#endif

	loggingoutputstdout = 0;
	loggingoutputstderr = 0;

#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_exit(&l_loglock);
#endif
}

/* */
void capwap_logging_enable_console(int error) {
#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_enter(&l_loglock);
#endif

	/* Enable only one of stdout/stderr */
	loggingoutputstdout = (error ? 0 : 1);
	loggingoutputstderr = !loggingoutputstdout;

#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_exit(&l_loglock);
#endif
}

/* */
void capwap_logging_disable_console(void) {
#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_enter(&l_loglock);
#endif

	loggingoutputstdout = 0;
	loggingoutputstderr = 0;

#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_exit(&l_loglock);
#endif
}

/* */
#ifdef ENABLE_LOGGING
void capwap_logging_printf(int level, const char* format, ...) {
	va_list args;
	char prefix[256];

	va_start(args, format); 

#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_enter(&l_loglock);
#endif

	if ((logginglevel != CAPWAP_LOGGING_NONE) && (level <= logginglevel)) {
		prefix_logging(level, prefix);

		if (loggingoutputstdout || loggingoutputstderr) {
			FILE* output = (loggingoutputstdout ? stdout : stderr);

			fprintf(output, prefix);
			vfprintf(output, format, args);
			fprintf(output, "\n");
			fflush(output);
		}
	}

#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_exit(&l_loglock);
#endif

	va_end(args);
}
#endif
