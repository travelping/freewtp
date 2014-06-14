#include <linux/module.h>
#include <linux/kernel.h>
#include "netlinkapp.h"

/* */
static int __init smartcapwap_init(void) {
	int result = 0;

	/* */
	result = nlsmartcapwap_init();

	return result;
}
module_init(smartcapwap_init);

/* */
static void __exit smartcapwap_exit(void) {
	nlsmartcapwap_exit();
}
module_exit(smartcapwap_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Massimo Vellucci <vemax78@gmail.com>");
MODULE_DESCRIPTION("SmartCAPWAP WTP Data Channel Module");
