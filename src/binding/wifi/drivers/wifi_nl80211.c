#include "wifi_drivers.h"
#include <sys/types.h>
#include <unistd.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>

/* Compatibility functions */
#if !defined(HAVE_LIBNL20) && !defined(HAVE_LIBNL30)
#define nl_sock nl_handle
static uint32_t port_bitmap[32] = { 0 };

static struct nl_sock* nl_socket_alloc_cb(void* cb) {
	int i;
	struct nl_sock* handle;
	uint32_t pid = getpid() & 0x3FFFFF;

	handle = nl_handle_alloc_cb(cb);
	for (i = 0; i < 1024; i++) {
		if (port_bitmap[i / 32] & (1 << (i % 32))) {
			continue;
		}

		port_bitmap[i / 32] |= 1 << (i % 32);
		pid += i << 22;
		break;
	}

	nl_socket_set_local_port(handle, pid);
	return handle;
}

static void nl_socket_free(struct nl_sock* handle) {
	uint32_t port = nl_socket_get_local_port(handle);

	port >>= 22;
	port_bitmap[port / 32] &= ~(1 << (port % 32));

	nl_handle_destroy(handle);
}
#endif

/* */
wifi_device_handle nl80211_device_init(wifi_global_handle handle, struct device_init_params* params) {
	return NULL;
}

/* */
void nl80211_device_deinit(wifi_device_handle handle) {
}

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
	.global_deinit = nl80211_global_deinit,
	.device_init = nl80211_device_init,
	.device_deinit = nl80211_device_deinit
};
