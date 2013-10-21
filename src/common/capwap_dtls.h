#ifndef __CAPWAP_DTLS_HEADER__
#define __CAPWAP_DTLS_HEADER__

#include "capwap_list.h"

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

#define CAPWAP_DTLS_CONTROL_SESSION				0
#define CAPWAP_DTLS_DATA_SESSION				1

#define CAPWAP_COOKIE_SECRET_LENGTH				16

#define CAPWAP_ERROR_AGAIN						0
#define CAPWAP_ERROR_SHUTDOWN					-1
#define CAPWAP_ERROR_CLOSE						-2

/* */
struct capwap_dtls_context {
	int type;
	int mode;

	void* sslcontext;

	/* Cookie */
	unsigned char cookie[CAPWAP_COOKIE_SECRET_LENGTH];

	union {
		struct {
			char* identity;
			unsigned char* pskkey;
			unsigned int pskkeylength;
		} presharedkey;

		struct {
			char* pwdprivatekey;				/* Password for private key */
		} cert;
	};
};

/* */
struct capwap_dtls {
	int enable;
	int action;
	int session;

	void* sslsession;

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

			/* Password for private key */
			char* pwdprivatekey;
		} cert;
	};
};

/* */
struct capwap_app_data {
	unsigned char* cookie;
};

/* */
typedef int(*capwap_bio_send)(struct capwap_dtls* dtls, char* buffer, int length, void* param);

int capwap_crypt_init();
void capwap_crypt_free();

int capwap_crypt_createcontext(struct capwap_dtls_context* dtlscontext, struct capwap_dtls_param* param);
void capwap_crypt_freecontext(struct capwap_dtls_context* dtlscontext);

int capwap_crypt_createsession(struct capwap_dtls* dtls, int sessiontype, struct capwap_dtls_context* dtlscontext, capwap_bio_send biosend, void* param);
void capwap_crypt_freesession(struct capwap_dtls* dtls);

int capwap_crypt_open(struct capwap_dtls* dtls, struct sockaddr_storage* peeraddr);
void capwap_crypt_close(struct capwap_dtls* dtls);
void capwap_crypt_change_bio_send(struct capwap_dtls* dtls, capwap_bio_send biosend, void* param);
void capwap_crypt_change_dtls(struct capwap_dtls* dtls, struct capwap_dtls* newdtls);

int capwap_crypt_sendto(struct capwap_dtls* dtls, int sock, void* buffer, int size, struct sockaddr_storage* sendfromaddr, struct sockaddr_storage* sendtoaddr);
int capwap_crypt_sendto_fragmentpacket(struct capwap_dtls* dtls, int sock, struct capwap_list* fragmentlist, struct sockaddr_storage* sendfromaddr, struct sockaddr_storage* sendtoaddr);
int capwap_decrypt_packet(struct capwap_dtls* dtls, void* encrybuffer, int size, void* plainbuffer, int maxsize);

int capwap_sanity_check_dtls_clienthello(void* buffer, int buffersize);

#endif /* __CAPWAP_DTLS_HEADER__ */
