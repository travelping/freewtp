#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

/* */
void wtp_dfa_state_idle(void) {
	long discoveryinterval;

	/* Remove teardown */
	g_wtp.teardown = 0;
	capwap_timeout_unsetall(g_wtp.timeout);

	/* */
	if (!g_wtp.acdiscoveryrequest && (g_wtp.acpreferedarray->count > 0)) {
		while (g_wtp.acpreferedselected < g_wtp.acpreferedarray->count) {
			union sockaddr_capwap localaddr;
			union sockaddr_capwap peeraddr;

			/* Found in configuration file the AC address */
			memcpy(&peeraddr, capwap_array_get_item_pointer(g_wtp.acpreferedarray, g_wtp.acpreferedselected), sizeof(union sockaddr_capwap));

			/* Next AC */
			g_wtp.acpreferedselected++;

			/* Retrieve local address */
			if (!capwap_network_get_localaddress(&localaddr, &peeraddr, g_wtp.net.bindiface)) {
				CAPWAP_SET_NETWORK_PORT(&localaddr, CAPWAP_GET_NETWORK_PORT(&g_wtp.net.localaddr));

				/* */
				capwap_crypt_setconnection(&g_wtp.dtls, g_wtp.net.socket, &localaddr, &peeraddr);

				/* */
				if (!g_wtp.enabledtls) {
					wtp_send_join();			/* Bypass DTLS connection */
				} else {
					wtp_start_dtlssetup();		/* Create DTLS connection */
				}

				return;
			}
		}
	}

	/* Discovery AC */
	g_wtp.acpreferedselected = 0;

	/* Set discovery interval */
	g_wtp.discoverycount = 0;
	discoveryinterval = capwap_get_rand(g_wtp.discoveryinterval - WTP_MIN_DISCOVERY_INTERVAL) + WTP_MIN_DISCOVERY_INTERVAL;

	/* Change state */
	wtp_dfa_change_state(CAPWAP_DISCOVERY_STATE);

	/* Wait before send Discovery Request */
	capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, discoveryinterval, wtp_dfa_state_discovery_timeout, NULL, NULL);
}
