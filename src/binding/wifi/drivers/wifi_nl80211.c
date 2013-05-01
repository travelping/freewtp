#include "wifi_drivers.h"











/* */
static wifi_global_handle nl80211_global_init(void) {
	return NULL;
}

/* */
void nl80211_global_deinit(wifi_global_handle handle) {
}

/* Driver function */
const struct wifi_driver_ops wifi_driver_nl80211_ops = {
	.name = "nl80211",
	.description = "Linux nl80211/cfg80211",
	.global_init = nl80211_global_init,
	.global_deinit = nl80211_global_deinit
};
