#ifndef __CAPWAP_DTLS_HEADER__
#define __CAPWAP_DTLS_HEADER__

#include "capwap_list.h"
#include "capwap_network.h"

#define CAPWAP_DTLS_CLIENT						0
#define CAPWAP_DTLS_SERVER						1

#define CAPWAP_DTLS_MODE_NONE					0
#define CAPWAP_DTLS_MODE_CERTIFICATE			1
#define CAPWAP_DTLS_MODE_PRESHAREDKEY			2

#define CAPWAP_DTLS_ACTION_NONE					0
#define CAPWAP_DTLS_ACTION_HANDSHAKE			1
#define CAPWAP_DTLS_ACTION_DATA					2
#define CAPWAP_DTLS_ACTION_SHUTDOWN				3
#define CAPWAP_DTLS_ACTION_ERROR				4

#define CAPWAP_HANDSHAKE_ERROR					-1
#define CAPWAP_HANDSHAKE_CONTINUE				0
#define CAPWAP_HANDSHAKE_COMPLETE				1

#define CAPWAP_ERROR_AGAIN						0
#define CAPWAP_ERROR_SHUTDOWN					-1
#define CAPWAP_ERROR_CLOSE						-2

/* */
struct capwap_dtls;

/* */
struct capwap_dtls_context {
	int type;
	int mode;

	void* sslcontext;

	union {
		struct {
			char* identity;
			unsigned char* pskkey;
			unsigned int pskkeylength;
		} presharedkey;
	};
};

/* */
struct capwap_dtls {
	int enable;
	int action;

	/* */
	void* sslsession;
	struct capwap_dtls_context* dtlscontext;

	/* */
	int sock;
	union sockaddr_capwap localaddr;
	union sockaddr_capwap peeraddr;

	/* Buffer read */
	void* buffer;
	int length;
};

/* */
struct capwap_dtls_param {
	int type;
	int mode;

	union {
		struct {
			char* hint;
			char* identity;
			char* pskkey;
		} presharedkey;

		struct {
			/* Certificate files */
			char* filecert;
			char* filekey;
			char* fileca;
		} cert;
	};
};

/* */
int capwap_crypt_init();
void capwap_crypt_free();

int capwap_crypt_createcontext(struct capwap_dtls_context* dtlscontext, struct capwap_dtls_param* param);
void capwap_crypt_freecontext(struct capwap_dtls_context* dtlscontext);

void capwap_crypt_setconnection(struct capwap_dtls* dtls, int sock, union sockaddr_capwap* localaddr, union sockaddr_capwap* peeraddr);
int capwap_crypt_createsession(struct capwap_dtls* dtls, struct capwap_dtls_context* dtlscontext);
void capwap_crypt_freesession(struct capwap_dtls* dtls);

int capwap_crypt_open(struct capwap_dtls* dtls);
void capwap_crypt_close(struct capwap_dtls* dtls);

int capwap_crypt_sendto(struct capwap_dtls* dtls, void* buffer, int size);
int capwap_crypt_sendto_fragmentpacket(struct capwap_dtls* dtls, struct capwap_list* fragmentlist);
int capwap_decrypt_packet(struct capwap_dtls* dtls, void* encrybuffer, int size, void* plainbuffer, int maxsize);

int capwap_crypt_has_dtls_clienthello(void* buffer, int buffersize);

#endif /* __CAPWAP_DTLS_HEADER__ */
