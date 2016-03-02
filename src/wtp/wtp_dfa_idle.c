#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

static int wtp_join_prefered_ac()
{
	if (g_wtp.acdiscoveryrequest ||
	    g_wtp.acpreferedarray->count == 0)
		/* goto discovery */
		return -1;

	while (g_wtp.acpreferedselected < g_wtp.acpreferedarray->count)
	{
		union sockaddr_capwap localaddr;
		union sockaddr_capwap *peeraddr;

		/* Found in configuration file the AC address */
		peeraddr = capwap_array_get_item_pointer(g_wtp.acpreferedarray,
							 g_wtp.acpreferedselected);

		/* Next AC */
		g_wtp.acpreferedselected++;

		/* restart and connect the control Socket */
		capwap_close_sockets(&g_wtp.net);
		if (capwap_bind_sockets(&g_wtp.net) < 0) {
			capwap_logging_fatal("Cannot bind control address");
			return -1;
		}

		if (capwap_connect_socket(&g_wtp.net, peeraddr) < 0) {
			capwap_logging_fatal("Cannot bind control address");
			capwap_close_sockets(&g_wtp.net);
			return -1;
		}

		/* Retrieve local address */
		if (capwap_getsockname(&g_wtp.net, &localaddr) < 0) {
			capwap_logging_fatal("Cannot get local endpoint address");
			capwap_close_sockets(&g_wtp.net);
			return -1;
		}

		/* */
		capwap_crypt_setconnection(&g_wtp.dtls, g_wtp.net.socket, &localaddr, peeraddr);

		/* */
		if (!g_wtp.enabledtls) {
			wtp_send_join();		/* Bypass DTLS connection */
		} else {
			wtp_start_dtlssetup();		/* Create DTLS connection */
		}

		return 0;
	}

	return -1;
}

/* */
void wtp_dfa_state_idle(void) {
	long discoveryinterval;

	/* Remove teardown */
	g_wtp.teardown = 0;
	capwap_timeout_unsetall(g_wtp.timeout);

	if (wtp_join_prefered_ac() == 0)
		return;

	if (g_wtp.net.socket < 0)
		if (capwap_bind_sockets(&g_wtp.net) < 0) {
			capwap_logging_fatal("Cannot bind control address");
			exit(-1);
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
