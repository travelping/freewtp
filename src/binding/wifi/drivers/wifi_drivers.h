#ifndef __WIFI_DRIVERS_HEADER__
#define __WIFI_DRIVERS_HEADER__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "capwap_debug.h"
#include "capwap_logging.h"

/* */
typedef void* wifi_global_handle;
typedef void* wifi_device_handle;

/* */
struct device_init_params {
	char* ifname;
};

/* */
struct wifi_driver_ops {
	const char* name;				/* Name of wifi driver */
	const char* description;		/* Description of wifi driver */

	/* Global initialize driver */
	wifi_global_handle (*global_init)(void);
	void (*global_deinit)(wifi_global_handle handle);

	/* Initialize device */
	wifi_device_handle (*device_init)(wifi_global_handle handle, struct device_init_params* params);
	void (*device_deinit)(wifi_device_handle handle);
};

/* Initialize wifi driver engine */
int wifi_init_driver(void);
void wifi_free_driver(void);

#endif /* __WIFI_DRIVERS_HEADER__ */
