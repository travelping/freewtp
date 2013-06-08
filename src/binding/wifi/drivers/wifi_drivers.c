#include "wifi_drivers.h"
#include <unistd.h>
#include <sys/ioctl.h>

#include "capwap_array.h"

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

/* Radio instance */
static struct capwap_array* wifi_device = NULL;

/* */
int wifi_init_driver(void) {
	int i;

	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		/* Initialize driver */
		ASSERT(wifi_driver[i].ops->global_init != NULL);
		wifi_driver[i].handle = wifi_driver[i].ops->global_init();
	}

	/* Device handler */
	wifi_device = capwap_array_create(sizeof(struct wifi_device), 0, 1);

	return 0;
}

/* */
void wifi_free_driver(void) {
	unsigned long i;

	/* Free device */
	if (wifi_device) {
		for (i = 0; i < wifi_device->count; i++) {
			struct wifi_device* device = (struct wifi_device*)capwap_array_get_item_pointer(wifi_device, i);
			if (device->handle && device->instance->ops->device_deinit) {
				device->instance->ops->device_deinit(device->handle);
			}
		}

		capwap_array_free(wifi_device);
	}

	/* Free driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		if (wifi_driver[i].ops->global_deinit) {
			wifi_driver[i].ops->global_deinit(wifi_driver[i].handle);
		}
	}
}

/* */
int wifi_create_device(int radioid, char* ifname, char* driver) {
	int i;
	int length;
	int result = -1;

	ASSERT(radioid > 0);
	ASSERT(ifname != NULL);
	ASSERT(driver != NULL);

	/* Check */
	length = strlen(ifname);
	if ((length <= 0) || (length >= IFNAMSIZ)) {
		capwap_logging_warning("Wifi device name error: %s", ifname);
		return -1;
	} else if (wifi_device->count >= radioid) {
		capwap_logging_warning("Wifi device RadioID already used: %d", radioid);
		return -1;
	}

	/* Search driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		if (!strcmp(driver, wifi_driver[i].ops->name)) {
			wifi_device_handle devicehandle;
			struct device_init_params params = {
				.ifname = ifname
			};

			/* Device init */
			ASSERT(wifi_driver[i].ops->device_init);
			devicehandle = wifi_driver[i].ops->device_init(wifi_driver[i].handle, &params);
			if (devicehandle) {
				/* Register new device */
				struct wifi_device* device = (struct wifi_device*)capwap_array_get_item_pointer(wifi_device, radioid);
				device->handle = devicehandle;
				device->instance = &wifi_driver[i];

				result = 0;
			}

			break;
		}
	}

	return result;
}

/* */
void wifi_iface_updown(int sock, const char* ifname, int up) {
	int localsock = -1;
	struct ifreq ifreq;

	ASSERT(ifname != NULL);
	ASSERT(*ifname != 0);

	/* Check if build local socket */
	if (sock < 0) {
		localsock = socket(AF_PACKET, SOCK_RAW, 0);
		if (localsock < 0) {
			return;
		} else {
			sock = localsock;
		}
	}

	/* Change link state of interface */
	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, ifname);
	if (!ioctl(sock, SIOCGIFFLAGS, &ifreq)) {
		if (up) {
			ifreq.ifr_flags |= IFF_UP;
		} else {
			ifreq.ifr_flags &= ~IFF_UP;
		}

		ioctl(sock, SIOCSIFFLAGS, &ifreq);
	}

	/* Free local socket */
	if (localsock >= 0) {
		close(localsock);
	}
}
