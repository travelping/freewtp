#include "config.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include "netlinkapp.h"

/* */
static int __init smartcapwap_ac_init(void) {
	int ret;

	TRACEKMOD("### smartcapwap_ac_init\n");

	/* Initialize netlink */
	ret = sc_netlink_init();
	if (ret) {
		return ret;
	}

	return ret;
}
module_init(smartcapwap_ac_init);

/* */
static void __exit smartcapwap_ac_exit(void) {
	TRACEKMOD("### smartcapwap_ac_exit\n");

	sc_netlink_exit();
}
module_exit(smartcapwap_ac_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Massimo Vellucci <vemax78@gmail.com>");
MODULE_DESCRIPTION("SmartCAPWAP AC Data Channel Module");
