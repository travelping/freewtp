#ifndef __KMOD_AC_IFACE_HEADER__
#define __KMOD_AC_IFACE_HEADER__

/* */
int sc_iface_create(const char* ifname, uint16_t mtu);
int sc_iface_delete(uint32_t ifindex);

void sc_iface_closeall(void);

#endif /* __KMOD_AC_IFACE_HEADER__ */
