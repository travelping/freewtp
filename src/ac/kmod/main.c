#include <linux/module.h>
#include <linux/kernel.h>
#include "netlinkapp.h"

/* */
static int __init smartcapwap_ac_init(void) {
	int result = 0;

	/* */
	result = nlsmartcapwap_ac_init();

	return result;
}
module_init(smartcapwap_ac_init);

/* */
static void __exit smartcapwap_ac_exit(void) {
	nlsmartcapwap_ac_exit();
}
module_exit(smartcapwap_ac_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Massimo Vellucci <vemax78@gmail.com>");
MODULE_DESCRIPTION("SmartCAPWAP AC Data Channel Module");
