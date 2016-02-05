#ifndef __KMOD_CONFIG_HEADER__
#define __KMOD_CONFIG_HEADER__

#define DEBUGKMOD 1

#ifdef DEBUGKMOD
#define TRACEKMOD(s, args...)				printk("(%d) " s, smp_processor_id(), ##args)
#else
#define TRACEKMOD(s, args...)
#endif

#endif /* __KMOD_CONFIG_HEADER__ */

