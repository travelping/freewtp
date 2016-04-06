#ifndef __CAPWAP_LOGGING_HEADER__
#define __CAPWAP_LOGGING_HEADER__

#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

#include <syslog.h>
#define LOG_TO_SYSLOG

/* Logging level */
#define LOG_NONE    -1

/* Logging initialize function */
void capwap_logging_init();
void capwap_logging_close();

/* */
void capwap_logging_verboselevel(int level);

/* */
void capwap_logging_disable_allinterface();
void capwap_logging_enable_console(int error);
void capwap_logging_disable_console(void);

/* */
#ifdef ENABLE_LOGGING
void __log_printf(int level, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
void __log_hexdump(int level, const char *title, const unsigned char *data, size_t len);
void __log_syslog(int level, const char* format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

#ifdef DISABLE_LOGGING_DEBUG

#define log_printf(level, f, args...)					\
	do {								\
		if ((level) != LOG_DEBUG)				\
			__log_printf((level), (f), ##args);		\
	} while (0)
#define log_hexdump(level, title, data, len)				\
	do {								\
		if ((level) != LOG_DEBUG)				\
			__log_hexdump((level), (title), (data), (len));	\
	} while (0)

#else

#ifdef LOG_TO_SYSLOG
#define log_printf(level, f, args...)			\
	__log_syslog((level), (f), ##args)
#else
#define log_printf(level, f, args...)			\
	__log_printf((level), (f), ##args)
#endif
#define log_hexdump(level, title, data, len)		\
	__log_hexdump((level), (title), (data), (len))
#endif

#else
#define log_printf(l, f, args...) do { } while (0)
#define log_hexdump(l, t, d, len) do { } while (0)
#endif

#endif /* __CAPWAP_LOGGING_HEADER__ */
