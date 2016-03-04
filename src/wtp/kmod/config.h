#ifndef __KMOD_CONFIG_HEADER__
#define __KMOD_CONFIG_HEADER__

// #define DEBUGKMOD 1

#ifdef DEBUGKMOD
#define TRACEKMOD(s, args...)				printk(s, ##args)
#else
#define TRACEKMOD(s, args...)
#endif

#endif /* __KMOD_CONFIG_HEADER__ */

