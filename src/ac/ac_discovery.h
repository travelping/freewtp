#ifndef __AC_DISCOVERY_HEADER__
#define __AC_DISCOVERY_HEADER__

int ac_discovery_start(void);
void ac_discovery_stop(void);
void ac_discovery_add_packet(void* buffer, int buffersize, int sock, union sockaddr_capwap* sender);

#endif /* __AC_DISCOVERY_HEADER__ */
