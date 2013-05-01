#ifndef __CAPWAP_LOGGING_HEADER__
#define __CAPWAP_LOGGING_HEADER__

/* Logging level */
#define CAPWAP_LOGGING_NONE			0
#define CAPWAP_LOGGING_FATAL		1
#define CAPWAP_LOGGING_ERROR		2
#define CAPWAP_LOGGING_WARNING		3
#define CAPWAP_LOGGING_INFO			4
#define CAPWAP_LOGGING_DEBUG		5

/* Logging initialize function */
void capwap_logging_init();
void capwap_logging_close();

/* */
void capwap_logging_verboselevel(unsigned int level);

/* */
void capwap_logging_disable_allinterface();
void capwap_logging_enable_console(int error);

/* */
#ifdef ENABLE_LOGGING
void capwap_logging_printf(int level, const char *format, ...);
#else
#define capwap_logging_printf(l, f, args...)
#endif

/* */
#define capwap_logging_fatal(f, args...)							capwap_logging_printf(CAPWAP_LOGGING_FATAL, f, ##args)
#define capwap_logging_error(f, args...)							capwap_logging_printf(CAPWAP_LOGGING_ERROR, f, ##args)
#define capwap_logging_warning(f, args...)							capwap_logging_printf(CAPWAP_LOGGING_WARNING, f, ##args)
#define capwap_logging_info(f, args...)								capwap_logging_printf(CAPWAP_LOGGING_INFO, f, ##args)
#define capwap_logging_debug(f, args...)							capwap_logging_printf(CAPWAP_LOGGING_DEBUG, f, ##args)

#endif /* __CAPWAP_LOGGING_HEADER__ */
