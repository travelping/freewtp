#ifndef __WIFI_DRIVERS_HEADER__
#define __WIFI_DRIVERS_HEADER__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

#include "capwap_debug.h"
#include "capwap_logging.h"

/* */
#define WIFI_DRIVER_NAME_SIZE			16

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

/* */
struct wifi_driver_instance {
	struct wifi_driver_ops* ops;						/* Driver functions */
	wifi_global_handle handle;							/* Global instance handle */
};

/* */
struct wifi_device {
	wifi_device_handle handle;							/* Device handle */
	struct wifi_driver_instance* instance;				/* Driver instance */
};

/* Initialize wifi driver engine */
int wifi_init_driver(void);
void wifi_free_driver(void);

/* */
int wifi_create_device(int radioid, char* ifname, char* driver);

#endif /* __WIFI_DRIVERS_HEADER__ */
