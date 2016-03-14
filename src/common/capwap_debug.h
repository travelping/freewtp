#ifndef __CAPWAP_DEBUG_HEADER__
#define __CAPWAP_DEBUG_HEADER__

#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

#ifdef DEBUG

#define ASSERT(expr)				if (!(expr)) { capwap_logging_fatal("Assertion failed \'%s\': %s(%d)", #expr, __FILE__, __LINE__); capwap_exit(CAPWAP_ASSERT_CONDITION); }

/* Custom memory management */
#define capwap_alloc(x)				capwap_alloc_debug(x, __FILE__, __LINE__)
void* capwap_alloc_debug(size_t size, const char* file, const int line);
#define capwap_free(x)				capwap_free_debug(x, __FILE__, __LINE__)
void capwap_free_debug(void* p, const char* file, const int line);

int capwap_check_memory_leak(int verbose);
void capwap_dump_memory(void);

#ifdef USE_DEBUG_BACKTRACE
void capwap_backtrace_callstack(void);
#else
#define capwap_backtrace_callstack()
#endif

#else

#define DEBUG_BREAKPOINT()

#define ASSERT(expr)

/* Standard memory management */
#define capwap_alloc(l)					({ void* __x = malloc(l); if (!__x) capwap_outofmemory(); __x; })
#define capwap_free(x)					free(x)
#define capwap_check_memory_leak(x)			(0)
#define capwap_dump_memory()
#define capwap_backtrace_callstack()

#endif

#endif /* __CAPWAP_DEBUG_HEADER__ */

