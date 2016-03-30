#ifndef __CAPWAP_LOGGING_HEADER__
#define __CAPWAP_LOGGING_HEADER__

#include <syslog.h>

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
void log_printf(int level, const char *format, ...);
void log_hexdump(int level, const char *title, const unsigned char *data, size_t len);
#else
#define log_printf(l, f, args...) do { } while (0)
#define log_hexdump(l, t, d, len) do { } while (0)
#endif

#define capwap_logging_printf log_printf
#define capwap_logging_hexdump log_hexdump

/* */
#define capwap_logging_fatal(f, args...)	\
	log_printf(LOG_EMERG, f, ##args)
#define capwap_logging_error(f, args...)	\
	log_printf(LOG_ERR, f, ##args)
#define capwap_logging_warning(f, args...)	\
	log_printf(LOG_WARNING, f, ##args)
#define capwap_logging_info(f, args...)		\
	log_printf(LOG_INFO, f, ##args)

#ifdef DISABLE_LOGGING_DEBUG
#define capwap_logging_debug(f, args...)
#else
#define capwap_logging_debug(f, args...)	\
	log_printf(LOG_DEBUG, f, ##args)
#endif

#endif /* __CAPWAP_LOGGING_HEADER__ */
