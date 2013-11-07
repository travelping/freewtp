#include "capwap.h"
#include "capwap_dfa.h"

#ifdef DEBUG

static char* l_nameofstate[] = {
	"START",								/* CAPWAP_START_STATE */
	"IDLE",									/* CAPWAP_IDLE_STATE */
	"DISCOVERY",							/* CAPWAP_DISCOVERY_STATE */
	"SULKING",								/* CAPWAP_SULKING_STATE */
	"DTLS_CONNECT",							/* CAPWAP_DTLS_CONNECT_STATE */
	"DTLS_TEARDOWN",						/* CAPWAP_DTLS_TEARDOWN_STATE */
	"JOIN",									/* CAPWAP_JOIN_STATE */
	"POST_JOIN",							/* CAPWAP_POSTJOIN_STATE */
	"IMAGE_DATA",							/* CAPWAP_IMAGE_DATA_STATE */
	"CONFIGURE",							/* CAPWAP_CONFIGURE_STATE */
	"RESET",								/* CAPWAP_RESET_STATE */
	"DATA_CHECK",							/* CAPWAP_DATA_CHECK_STATE */
	"DATA_CHECK_TO_RUN",					/* CAPWAP_DATA_CHECK_TO_RUN_STATE */
	"RUN",									/* CAPWAP_RUN_STATE */
	"DEAD"									/* CAPWAP_DEAD_STATE */
};

/* */
char* capwap_dfa_getname(int state) {
	if ((state < 0) || (state > CAPWAP_LAST_STATE)) {
		return "";
	}

	return l_nameofstate[state];
}

#endif
