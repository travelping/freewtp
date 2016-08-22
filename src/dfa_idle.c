#include "wtp.h"
#include "capwap_dfa.h"
#include "dfa.h"

static int wtp_join_prefered_ac()
{
	if (g_wtp.acdiscoveryrequest ||
	    g_wtp.acpreferedarray->count == 0)
		/* goto discovery */
		return -1;

	while (g_wtp.acpreferedselected < g_wtp.acpreferedarray->count)
	{
		union sockaddr_capwap localaddr;
		struct addr_capwap *peeraddr;

		/* Found in configuration file the AC address */
		peeraddr = capwap_array_get_item_pointer(g_wtp.acpreferedarray,
												 g_wtp.acpreferedselected);


		/* Next AC */
		g_wtp.acpreferedselected++;

		/* restart and connect the control Socket */
		wtp_socket_io_stop();
		capwap_close_sockets(&g_wtp.net);
		if (capwap_bind_sockets(&g_wtp.net) < 0) {
			log_printf(LOG_EMERG, "Cannot bind control address");
			return -1;
		}
		wtp_socket_io_start();

		if(!peeraddr->resolved) {
			if (capwap_address_from_string(peeraddr->fqdn, &peeraddr->sockaddr)) {
				if (!CAPWAP_GET_NETWORK_PORT(&peeraddr->sockaddr)) {
					CAPWAP_SET_NETWORK_PORT(&peeraddr->sockaddr, CAPWAP_CONTROL_PORT);
				}
				peeraddr->resolved = 1;
			} else {
				log_printf(LOG_INFO, "%s:%d Could not resolve application.acprefered.host %s", __FILE__, __LINE__, peeraddr->fqdn);
			}
		}

		if (capwap_connect_socket(&g_wtp.net, &peeraddr->sockaddr) < 0) {
			log_printf(LOG_EMERG, "Cannot bind control address");
			wtp_socket_io_stop();
			capwap_close_sockets(&g_wtp.net);
			return -1;
		}

		/* Retrieve local address */
		if (capwap_getsockname(&g_wtp.net, &localaddr) < 0) {
			log_printf(LOG_EMERG, "Cannot get local endpoint address");
			wtp_socket_io_stop();
			capwap_close_sockets(&g_wtp.net);
			return -1;
		}

		/* */
		capwap_crypt_setconnection(&g_wtp.dtls, g_wtp.net.socket, &localaddr, &peeraddr->sockaddr);

		/* */
		if (!g_wtp.enabledtls) {
			wtp_dfa_change_state(CAPWAP_JOIN_STATE);		/* Bypass DTLS connection */
		} else
			wtp_start_dtlssetup();		/* Create DTLS connection */

		return 0;
	}

	return -1;
}

/* */
void wtp_dfa_state_idle_enter(void)
{
	/* Remove teardown */
	g_wtp.teardown = 0;
	wtp_timeout_stop_all();

	if (wtp_join_prefered_ac() == 0)
		return;

	if (g_wtp.net.socket < 0) {
		if (capwap_bind_sockets(&g_wtp.net) < 0) {
			log_printf(LOG_EMERG, "Cannot bind control address");
			exit(-1);
		}
		wtp_socket_io_start();
	}

	/* Discovery AC */
	g_wtp.acpreferedselected = 0;

	/* Set discovery interval */
	g_wtp.discoverycount = 0;
	/* Change state */
	wtp_dfa_change_state(CAPWAP_DISCOVERY_STATE);

}
