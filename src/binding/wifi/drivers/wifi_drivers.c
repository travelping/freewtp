#include "wifi_drivers.h"

/* */
struct wifi_driver_instance {
	struct wifi_driver_ops* ops;		/* Driver functions */

	wifi_global_handle handle;			/* Global instance handle */
};

/* Declare enable wifi driver */
#ifdef ENABLE_WIFI_DRIVERS_NL80211
extern struct wifi_driver_ops wifi_driver_nl80211_ops;
#endif

static struct wifi_driver_instance wifi_driver[] = {
#ifdef ENABLE_WIFI_DRIVERS_NL80211
	{ &wifi_driver_nl80211_ops },
#endif
	{ NULL }
};

/* */
int wifi_init_driver(void) {
	int i;

	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		if (!wifi_driver[i].ops->global_init) {
			return -1;
		}

		/* Initialize driver */
		wifi_driver[i].handle = wifi_driver[i].ops->global_init();
	}

	return 0;
}

/* */
void wifi_free_driver(void) {
	int i;

	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		/* Free driver */
		if (wifi_driver[i].ops->global_deinit) {
			wifi_driver[i].ops->global_deinit(wifi_driver[i].handle);
		}
	}
}
