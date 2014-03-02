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
			/* Found in configuration file the AC address */
			memcpy(&g_wtp.acctrladdress, capwap_array_get_item_pointer(g_wtp.acpreferedarray, g_wtp.acpreferedselected), sizeof(struct sockaddr_storage));
			memcpy(&g_wtp.acdataaddress, &g_wtp.acctrladdress, sizeof(struct sockaddr_storage));
			CAPWAP_SET_NETWORK_PORT(&g_wtp.acdataaddress, CAPWAP_GET_NETWORK_PORT(&g_wtp.acdataaddress) + 1);

			/* Next AC */
			g_wtp.acpreferedselected++;

			/* Configure socket */
			capwap_get_network_socket(&g_wtp.net, &g_wtp.acctrlsock, capwap_get_socket(&g_wtp.net, g_wtp.acctrladdress.ss_family, IPPROTO_UDP, CAPWAP_CTRL_SOCKET));
			capwap_get_network_socket(&g_wtp.net, &g_wtp.acdatasock, capwap_get_socket(&g_wtp.net, g_wtp.acdataaddress.ss_family, (g_wtp.transport.type == CAPWAP_UDP_TRANSPORT ? IPPROTO_UDP : IPPROTO_UDPLITE), CAPWAP_DATA_SOCKET));

			/* Retrieve local address */
			if (capwap_get_localaddress_by_remoteaddress(&g_wtp.wtpctrladdress, &g_wtp.acctrladdress, g_wtp.net.bind_interface, (!(g_wtp.net.bind_ctrl_flags & CAPWAP_IPV6ONLY_FLAG) ? 1 : 0))) {
				struct sockaddr_storage sockinfo;
				socklen_t sockinfolen = sizeof(struct sockaddr_storage);

				memset(&sockinfo, 0, sizeof(struct sockaddr_storage));
				if (!getsockname(g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], (struct sockaddr*)&sockinfo, &sockinfolen)) {
					CAPWAP_SET_NETWORK_PORT(&g_wtp.wtpctrladdress, CAPWAP_GET_NETWORK_PORT(&sockinfo));

					/* */
					memcpy(&g_wtp.wtpdataaddress, &g_wtp.wtpctrladdress, sizeof(struct sockaddr_storage));
					CAPWAP_SET_NETWORK_PORT(&g_wtp.wtpdataaddress, CAPWAP_GET_NETWORK_PORT(&g_wtp.wtpdataaddress) + 1);

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
