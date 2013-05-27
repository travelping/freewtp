#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

/* */
int wtp_dfa_state_idle(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	if (!g_wtp.acdiscoveryrequest && (g_wtp.acpreferedarray->count > 0)) {
		/* Found in configuration file the AC address */
		memcpy(&g_wtp.acctrladdress, capwap_array_get_item_pointer(g_wtp.acpreferedarray, g_wtp.acpreferedselected), sizeof(struct sockaddr_storage));
		memcpy(&g_wtp.acdataaddress, &g_wtp.acctrladdress, sizeof(struct sockaddr_storage));
		CAPWAP_SET_NETWORK_PORT(&g_wtp.acdataaddress, CAPWAP_GET_NETWORK_PORT(&g_wtp.acdataaddress) + 1);
		
		/* Configure socket */
		capwap_get_network_socket(&g_wtp.net, &g_wtp.acctrlsock, capwap_get_socket(&g_wtp.net, g_wtp.acctrladdress.ss_family, IPPROTO_UDP, CAPWAP_CTRL_SOCKET));
		capwap_get_network_socket(&g_wtp.net, &g_wtp.acdatasock, capwap_get_socket(&g_wtp.net, g_wtp.acdataaddress.ss_family, (g_wtp.transport.type == CAPWAP_UDP_TRANSPORT ? IPPROTO_UDP : IPPROTO_UDPLITE), CAPWAP_DATA_SOCKET));

		/* */		
		g_wtp.acpreferedselected = (g_wtp.acpreferedselected + 1) % g_wtp.acpreferedarray->count;
		
		/* Connect */
		wtp_dfa_change_state(CAPWAP_IDLE_TO_DTLS_SETUP_STATE);
	} else {
		/* Search AC */
		wtp_dfa_change_state(CAPWAP_IDLE_TO_DISCOVERY_STATE);
	}
	
	capwap_kill_timeout(timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	return WTP_DFA_NO_PACKET;
}

/* Prepare to discovery AC */
int wtp_dfa_state_idle_to_discovery(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);

	/* Set discovery interval */
	g_wtp.dfa.rfcDiscoveryInterval = capwap_get_rand(g_wtp.dfa.rfcMaxDiscoveryInterval - WTP_MIN_DISCOVERY_INTERVAL) + WTP_MIN_DISCOVERY_INTERVAL;
	g_wtp.dfa.rfcDiscoveryCount = 0;
	
	/* Change state */
	wtp_dfa_change_state(CAPWAP_DISCOVERY_STATE);
	
	/* Wait before send Discovery Request */
	capwap_set_timeout(g_wtp.dfa.rfcDiscoveryInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	
	return WTP_DFA_DROP_PACKET;
}

/* Prepare to connect with AC */
int wtp_dfa_state_idle_to_dtlssetup(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	int status = WTP_DFA_ACCEPT_PACKET;
	
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);

	/* Retrieve local address */
	if (!capwap_get_localaddress_by_remoteaddress(&g_wtp.wtpctrladdress, &g_wtp.acctrladdress, g_wtp.net.bind_interface, (!(g_wtp.net.bind_ctrl_flags & CAPWAP_IPV6ONLY_FLAG) ? 1 : 0))) {
		wtp_dfa_change_state(CAPWAP_IDLE_STATE);
		status = WTP_DFA_NO_PACKET;
	} else {
		struct sockaddr_storage sockinfo;
		socklen_t sockinfolen = sizeof(struct sockaddr_storage);

		memset(&sockinfo, 0, sizeof(struct sockaddr_storage));
		if (getsockname(g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], (struct sockaddr*)&sockinfo, &sockinfolen) < 0) {
			wtp_dfa_change_state(CAPWAP_DTLS_SETUP_TO_SULKING_STATE);
			status = WTP_DFA_NO_PACKET; 
		} else {
			CAPWAP_SET_NETWORK_PORT(&g_wtp.wtpctrladdress, CAPWAP_GET_NETWORK_PORT(&sockinfo));
			
			/* */
			memcpy(&g_wtp.wtpdataaddress, &g_wtp.wtpctrladdress, sizeof(struct sockaddr_storage));
			CAPWAP_SET_NETWORK_PORT(&g_wtp.wtpdataaddress, CAPWAP_GET_NETWORK_PORT(&g_wtp.wtpdataaddress) + 1);
			
			/* */
			if (!g_wtp.enabledtls) {
				/* Bypass DTLS connection */
				wtp_dfa_change_state(CAPWAP_DTLS_CONNECT_TO_JOIN_STATE);
				status = WTP_DFA_NO_PACKET;
			} else {
				/* Create DTLS connection */
				wtp_dfa_change_state(CAPWAP_DTLS_SETUP_STATE);
				status = WTP_DFA_NO_PACKET;
			}
		}
	}
	
	return status;
}
