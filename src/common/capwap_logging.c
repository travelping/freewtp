#include <ctype.h>

#include "capwap.h"
#include "capwap_logging.h"

#ifdef CAPWAP_MULTITHREADING_ENABLE 
#include "capwap_lock.h"

static capwap_lock_t l_loglock;
#endif

/* */
static int logginglevel = LOG_NONE;
static int loggingoutputstdout = 0;
static int loggingoutputstderr = 0;

/* */
static char logginglevelid[] = { 'N', 'F', 'E', 'W', 'I', 'D' };

/* */
static void prefix_logging(int level, char* buffer) {
	time_t timenow;
	struct tm* tmnow;
#ifdef CAPWAP_MULTITHREADING_ENABLE
	pthread_t threadid = pthread_self();
#endif

	time(&timenow);
	tmnow = localtime(&timenow);

#ifdef CAPWAP_MULTITHREADING_ENABLE
	sprintf(buffer, "[%02d/%02d/%04d %02d:%02d:%02d] [%08x] <%c> ", tmnow->tm_mday, tmnow->tm_mon + 1, tmnow->tm_year + 1900, tmnow->tm_hour, tmnow->tm_min, tmnow->tm_sec, (unsigned int)threadid, logginglevelid[level]);
#else
	sprintf(buffer, "[%02d/%02d/%04d %02d:%02d:%02d] <%c> ", tmnow->tm_mday, tmnow->tm_mon + 1, tmnow->tm_year + 1900, tmnow->tm_hour, tmnow->tm_min, tmnow->tm_sec, logginglevelid[level]);
#endif
}

/* */
void capwap_logging_init() {
#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_init(&l_loglock);
#endif
#ifdef LOG_TO_SYSLOG
    openlog("capwap", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
#endif
}

/* */
void capwap_logging_close() {
#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_destroy(&l_loglock);
#endif
#ifdef LOG_TO_SYSLOG
    closelog();
#endif
}

/* */
void capwap_logging_verboselevel(int level) {
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
void __log_syslog(int level, const char* format, ...)
{
    int errsv = errno;
    va_list args;
    va_start(args, format);
    vsyslog(level, format, args);
    va_end(args);
    errno = errsv;
}

void __log_printf(int level, const char* format, ...)
{
	int errsv = errno;
	va_list args;
	char prefix[256];

	va_start(args, format);

#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_enter(&l_loglock);
#endif

	if (level <= logginglevel) {
		prefix_logging(level, prefix);

		if (loggingoutputstdout || loggingoutputstderr) {
			FILE* output = (loggingoutputstdout ? stdout : stderr);

			fprintf(output, "%s", prefix);
			vfprintf(output, format, args);
			fprintf(output, "\n");
			fflush(output);
		}
	}

#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_exit(&l_loglock);
#endif

	va_end(args);

	errno = errsv;
}

void __log_hexdump(int level, const char *title, const unsigned char *data, size_t len)
{
    int errsv = errno;
    char prefix[256];

	if (level > logginglevel)
		return;

#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_enter(&l_loglock);
#endif

	prefix_logging(level, prefix);

	if (loggingoutputstdout || loggingoutputstderr) {
		FILE* output = (loggingoutputstdout ? stdout : stderr);
		const uint8_t *pos = data;

                fprintf(output, "%s%s - hexdump(len=%zd):\n", prefix, title, len);
                while (len) {
			size_t llen;
			int i;

                        llen = len > 16 ? 16 : len;
                        fprintf(output, "%s ", prefix);
                        for (i = 0; i < llen; i++)
                                fprintf(output, " %02x", pos[i]);
                        for (i = llen; i < 16; i++)
                                fprintf(output, "   ");
                        fprintf(output, "   ");
                        for (i = 0; i < llen; i++) {
                                if (isprint(pos[i]))
                                        fprintf(output, "%c", pos[i]);
                                else
                                        fprintf(output, ".");
                        }
                        for (i = llen; i < 16; i++)
                                fprintf(output, " ");
                        fprintf(output, "\n");
                        pos += llen;
                        len -= llen;
                }
		fflush(output);
	}

#ifdef CAPWAP_MULTITHREADING_ENABLE
	capwap_lock_exit(&l_loglock);
#endif

	errno = errsv;
}

#endif
