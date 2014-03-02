#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

/* */
static void wtp_dfa_state_dtlsconnect_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	wtp_teardown_connection();
}

/* DTLS BIO send */
int wtp_bio_send(struct capwap_dtls* dtls, char* buffer, int length, void* param) {
	struct capwap_socket* socket = ((dtls->session == CAPWAP_DTLS_CONTROL_SESSION) ? &g_wtp.acctrlsock : &g_wtp.acdatasock);
	struct sockaddr_storage* wtpaddress = ((dtls->session == CAPWAP_DTLS_CONTROL_SESSION) ? &g_wtp.wtpctrladdress : &g_wtp.wtpdataaddress);
	struct sockaddr_storage* acaddress = ((dtls->session == CAPWAP_DTLS_CONTROL_SESSION) ? &g_wtp.acctrladdress : &g_wtp.acdataaddress);
	
	return capwap_sendto(socket->socket[socket->type], buffer, length, wtpaddress, acaddress);
}

/* */
void wtp_start_dtlssetup(void) {
	/* Create DTLS session */
	if (!capwap_crypt_createsession(&g_wtp.ctrldtls, CAPWAP_DTLS_CONTROL_SESSION, &g_wtp.dtlscontext, wtp_bio_send, NULL)) {
		wtp_dfa_change_state(CAPWAP_SULKING_STATE);
		capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_SILENT_INTERVAL, wtp_dfa_state_sulking_timeout, NULL, NULL);
	} else {
		if (capwap_crypt_open(&g_wtp.ctrldtls, &g_wtp.acctrladdress) == CAPWAP_HANDSHAKE_ERROR) {
			wtp_dfa_change_state(CAPWAP_SULKING_STATE);
			capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_SILENT_INTERVAL, wtp_dfa_state_sulking_timeout, NULL, NULL);
		} else {
			wtp_dfa_change_state(CAPWAP_DTLS_CONNECT_STATE);
			capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_DTLS_INTERVAL, wtp_dfa_state_dtlsconnect_timeout, NULL, NULL);
		}
	}
}

/* */
void wtp_start_datachannel(void) {
	struct capwap_list* txfragpacket;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	/* If need, create DTLS Data channel crypted */
	if (g_wtp.dtlsdatapolicy & CAPWAP_ACDESC_DTLS_DATA_CHANNEL_ENABLED) {
		if (!g_wtp.datadtls.enable) {
			/* Create DTLS data session before send data keepalive */
			if (capwap_crypt_createsession(&g_wtp.datadtls, CAPWAP_DTLS_DATA_SESSION, &g_wtp.dtlscontext, wtp_bio_send, NULL)) {
				if (capwap_crypt_open(&g_wtp.datadtls, &g_wtp.acdataaddress) == CAPWAP_HANDSHAKE_CONTINUE) {
					capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_DTLS_INTERVAL, wtp_dfa_state_dtlsconnect_timeout, NULL, NULL);		/* Wait complete dtls handshake */
				} else {
					wtp_teardown_connection();
				}
			} else {
				wtp_teardown_connection();
			}

			return;
		} else if (g_wtp.datadtls.action != CAPWAP_DTLS_ACTION_DATA) {
			wtp_teardown_connection();
			return;
		}
	}

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	capwap_header_set_keepalive_flag(&capwapheader, 1);
	txmngpacket = capwap_packet_txmng_create_data_message(&capwapheader, g_wtp.mtu);		/* CAPWAP_DONT_FRAGMENT */

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_SESSIONID, &g_wtp.sessionid);

	/* Data keepalive complete, get fragment packets into local list */
	txfragpacket = capwap_list_create();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, txfragpacket, 0);
	if (txfragpacket->count == 1) {
		/* Send Data keepalive to AC */
		if (capwap_crypt_sendto_fragmentpacket(&g_wtp.datadtls, g_wtp.acdatasock.socket[g_wtp.acdatasock.type], txfragpacket, &g_wtp.wtpdataaddress, &g_wtp.acdataaddress)) {
			/* Reset AC Prefered List Position */
			g_wtp.acpreferedselected = 0;

			/* Set timer */
			wtp_dfa_change_state(CAPWAP_RUN_STATE);
			capwap_timeout_unset(g_wtp.timeout, g_wtp.idtimercontrol);
			capwap_timeout_set(g_wtp.timeout, g_wtp.idtimerecho, g_wtp.echointerval, wtp_dfa_state_run_echo_timeout, NULL, NULL);
			capwap_timeout_set(g_wtp.timeout, g_wtp.idtimerkeepalivedead, WTP_DATACHANNEL_KEEPALIVEDEAD, wtp_dfa_state_run_keepalivedead_timeout, NULL, NULL);
		} else {
			/* Error to send packets */
			capwap_logging_debug("Warning: error to send data channel keepalive packet");
			wtp_teardown_connection();
		}
	} else {
		capwap_logging_debug("Warning: error to send data channel keepalive packet, fragment packet");
		wtp_teardown_connection();
	}

	/* Free packets manager */
	capwap_list_free(txfragpacket);
	capwap_packet_txmng_free(txmngpacket);
}

/* */
static void wtp_dfa_state_dtlsteardown_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	/* Free and reset resource */
	if (g_wtp.ctrldtls.enable) {
		capwap_crypt_freesession(&g_wtp.ctrldtls);
	}

	if (g_wtp.datadtls.enable) {
		capwap_crypt_freesession(&g_wtp.datadtls);
	}

	/* */
	if (g_wtp.acname.name) {
		capwap_free(g_wtp.acname.name);
		g_wtp.acname.name = NULL;
	}

	/* */
	wtp_free_reference_last_request();
	wtp_free_reference_last_response();
	wtp_free_packet_rxmng(0);
	wtp_free_packet_rxmng(1);

	/* */
	if (!g_wtp.running) {
		wtp_dfa_change_state(CAPWAP_DEAD_STATE);
	} else if ((g_wtp.faileddtlssessioncount >= WTP_FAILED_DTLS_SESSION_RETRY) || (g_wtp.faileddtlsauthfailcount >= WTP_FAILED_DTLS_SESSION_RETRY)) {
		wtp_dfa_change_state(CAPWAP_SULKING_STATE);
		capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_SILENT_INTERVAL, wtp_dfa_state_sulking_timeout, NULL, NULL);
	} else {
		wtp_dfa_change_state(CAPWAP_IDLE_STATE);
		wtp_dfa_state_idle();
	}
}

/* */
void wtp_dfa_state_dtlsteardown(struct capwap_parsed_packet* packet) {
}

/* Teardown connection */
void wtp_teardown_connection(void) {
	g_wtp.teardown = 1;

	/* DTSL Control */
	if (g_wtp.ctrldtls.enable) {
		capwap_crypt_close(&g_wtp.ctrldtls);
	}

	/* DTLS Data */
	if (g_wtp.datadtls.enable) {
		capwap_crypt_close(&g_wtp.datadtls);
	}

	/* */
	wtp_dfa_change_state(CAPWAP_DTLS_TEARDOWN_STATE);
	capwap_timeout_unsetall(g_wtp.timeout);
	capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_DTLS_SESSION_DELETE, wtp_dfa_state_dtlsteardown_timeout, NULL, NULL);
}
